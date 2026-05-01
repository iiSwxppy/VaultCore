using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Vault.Core.Items;
using Vault.Core.Serialization;

namespace Vault.Core;

/// <summary>
/// Single-file vault format (.vault).
///
/// FORMAT VERSION 3 (current):
///   Magic         : 4 bytes  "VLT1"
///   FormatVersion : u32 LE   = 3
///   ManifestLen   : u32 LE
///   Manifest      : JSON UTF-8 (length above), plaintext
///   ItemCount     : u32 LE
///   For each item:
///     Id (16) | Type (1) | CreatedMs (8) | UpdatedMs (8) | EnvLen (4) | Envelope
///   AuditCount    : u32 LE
///   For each audit entry:
///     TimestampMs (8) | EnvLen (4) | Envelope
///   TombstoneCount: u32 LE
///   For each tombstone:
///     Id (16) | DeletedMs (8)
///   HMAC-SHA256   : 32 bytes
///
/// Tombstones are stored PLAINTEXT (just id + timestamp). They contain no
/// sensitive content — only that "an item with this UUID existed once and
/// was deleted at this time". The HMAC over the body still binds them to
/// the rest of the file.
///
/// Versions 1 and 2 are read-compatible. v1 has no audit + no tombstones;
/// v2 has audit but no tombstones. On next save we promote to v3.
/// </summary>
public static class VaultFile
{
    public static readonly byte[] Magic = "VLT1"u8.ToArray();
    public const int CurrentFormatVersion = 3;
    private const int IdSize = 16;

    public sealed record EncryptedItem(
        Guid Id,
        ItemType Type,
        DateTimeOffset CreatedAt,
        DateTimeOffset UpdatedAt,
        byte[] Envelope);

    public sealed record EncryptedAuditEntry(
        DateTimeOffset Timestamp,
        byte[] Envelope);

    public sealed record VaultFileContents(
        VaultManifest Manifest,
        IReadOnlyList<EncryptedItem> Items,
        IReadOnlyList<EncryptedAuditEntry> AuditEntries,
        IReadOnlyList<Tombstone> Tombstones);

    public static void Write(
        string path,
        VaultManifest manifest,
        IReadOnlyList<EncryptedItem> items,
        IReadOnlyList<EncryptedAuditEntry> auditEntries,
        IReadOnlyList<Tombstone> tombstones,
        ReadOnlySpan<byte> hmacKey)
    {
        using var ms = new MemoryStream();
        WriteToStream(ms, manifest, items, auditEntries, tombstones);

        var body = ms.ToArray();
        var mac = HMACSHA256.HashData(hmacKey, body);

        var tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(body);
            fs.Write(mac);
            fs.Flush(flushToDisk: true);
        }
        if (File.Exists(path)) File.Replace(tmp, path, destinationBackupFileName: null);
        else File.Move(tmp, path);
    }

    private static void WriteToStream(
        Stream s,
        VaultManifest manifest,
        IReadOnlyList<EncryptedItem> items,
        IReadOnlyList<EncryptedAuditEntry> auditEntries,
        IReadOnlyList<Tombstone> tombstones)
    {
        s.Write(Magic);
        WriteU32(s, CurrentFormatVersion);

        var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, VaultJsonContext.Default.VaultManifest);
        WriteU32(s, (uint)manifestJson.Length);
        s.Write(manifestJson);

        WriteU32(s, (uint)items.Count);
        Span<byte> idBytes = stackalloc byte[IdSize];
        foreach (var item in items)
        {
            if (!item.Id.TryWriteBytes(idBytes)) throw new InvalidOperationException();
            s.Write(idBytes);
            s.WriteByte((byte)item.Type);
            WriteI64(s, item.CreatedAt.ToUnixTimeMilliseconds());
            WriteI64(s, item.UpdatedAt.ToUnixTimeMilliseconds());
            WriteU32(s, (uint)item.Envelope.Length);
            s.Write(item.Envelope);
        }

        WriteU32(s, (uint)auditEntries.Count);
        foreach (var entry in auditEntries)
        {
            WriteI64(s, entry.Timestamp.ToUnixTimeMilliseconds());
            WriteU32(s, (uint)entry.Envelope.Length);
            s.Write(entry.Envelope);
        }

        WriteU32(s, (uint)tombstones.Count);
        foreach (var tomb in tombstones)
        {
            if (!tomb.ItemId.TryWriteBytes(idBytes)) throw new InvalidOperationException();
            s.Write(idBytes);
            WriteI64(s, tomb.DeletedAt.ToUnixTimeMilliseconds());
        }
    }

    public static VaultFileContents Read(string path, ReadOnlySpan<byte> hmacKey)
    {
        var bytes = File.ReadAllBytes(path);
        return ReadFromBytes(bytes, hmacKey);
    }

    public static VaultFileContents ReadFromBytes(byte[] bytes, ReadOnlySpan<byte> hmacKey)
    {
        if (bytes.Length < Magic.Length + 4 + 32) throw new InvalidDataException("Vault file too short");

        var bodyLen = bytes.Length - 32;
        var body = bytes.AsSpan(0, bodyLen);
        var storedMac = bytes.AsSpan(bodyLen);

        var computedMac = HMACSHA256.HashData(hmacKey, body);
        if (!CryptographicOperations.FixedTimeEquals(computedMac, storedMac))
            throw new CryptographicException("Vault integrity check failed (HMAC mismatch). File tampered or wrong key.");

        var pos = 0;

        if (!body[..Magic.Length].SequenceEqual(Magic))
            throw new InvalidDataException("Bad magic bytes");
        pos += Magic.Length;

        var version = ReadU32(body, ref pos);
        if (version is < 1 or > 3)
            throw new InvalidDataException($"Unsupported format version {version}");

        var manifestLen = (int)ReadU32(body, ref pos);
        var manifestJson = body.Slice(pos, manifestLen);
        pos += manifestLen;
        var manifest = JsonSerializer.Deserialize(manifestJson, VaultJsonContext.Default.VaultManifest)
            ?? throw new InvalidDataException("Bad manifest");

        var itemCount = (int)ReadU32(body, ref pos);
        var items = new List<EncryptedItem>(itemCount);
        for (var i = 0; i < itemCount; i++)
        {
            var id = new Guid(body.Slice(pos, IdSize));
            pos += IdSize;
            var type = (ItemType)body[pos]; pos += 1;
            var createdMs = ReadI64(body, ref pos);
            var updatedMs = ReadI64(body, ref pos);
            var envLen = (int)ReadU32(body, ref pos);
            var env = body.Slice(pos, envLen).ToArray();
            pos += envLen;

            items.Add(new EncryptedItem(
                id, type,
                DateTimeOffset.FromUnixTimeMilliseconds(createdMs),
                DateTimeOffset.FromUnixTimeMilliseconds(updatedMs),
                env));
        }

        var audit = new List<EncryptedAuditEntry>();
        if (version >= 2 && pos < body.Length)
        {
            var auditCount = (int)ReadU32(body, ref pos);
            audit.Capacity = auditCount;
            for (var i = 0; i < auditCount; i++)
            {
                var ts = ReadI64(body, ref pos);
                var envLen = (int)ReadU32(body, ref pos);
                var env = body.Slice(pos, envLen).ToArray();
                pos += envLen;
                audit.Add(new EncryptedAuditEntry(DateTimeOffset.FromUnixTimeMilliseconds(ts), env));
            }
        }

        var tombstones = new List<Tombstone>();
        if (version >= 3 && pos < body.Length)
        {
            var count = (int)ReadU32(body, ref pos);
            tombstones.Capacity = count;
            for (var i = 0; i < count; i++)
            {
                var id = new Guid(body.Slice(pos, IdSize));
                pos += IdSize;
                var deletedMs = ReadI64(body, ref pos);
                tombstones.Add(new Tombstone(id, DateTimeOffset.FromUnixTimeMilliseconds(deletedMs)));
            }
        }

        return new VaultFileContents(manifest, items, audit, tombstones);
    }

    public static byte[] ItemAssociatedData(Guid id, ItemType type, DateTimeOffset created, DateTimeOffset updated)
    {
        var ad = new byte[IdSize + 1 + 8 + 8];
        var span = ad.AsSpan();
        if (!id.TryWriteBytes(span[..IdSize])) throw new InvalidOperationException();
        span[IdSize] = (byte)type;
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(IdSize + 1, 8), created.ToUnixTimeMilliseconds());
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(IdSize + 9, 8), updated.ToUnixTimeMilliseconds());
        return ad;
    }

    public static byte[] AuditAssociatedData(DateTimeOffset timestamp)
    {
        var ad = new byte[8 + 8];
        "audit-v1"u8.CopyTo(ad.AsSpan(0, 8));
        BinaryPrimitives.WriteInt64LittleEndian(ad.AsSpan(8, 8), timestamp.ToUnixTimeMilliseconds());
        return ad;
    }

    private static void WriteU32(Stream s, uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        s.Write(b);
    }

    private static void WriteI64(Stream s, long v)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(b, v);
        s.Write(b);
    }

    private static uint ReadU32(ReadOnlySpan<byte> b, ref int pos)
    {
        var v = BinaryPrimitives.ReadUInt32LittleEndian(b.Slice(pos, 4));
        pos += 4;
        return v;
    }

    private static long ReadI64(ReadOnlySpan<byte> b, ref int pos)
    {
        var v = BinaryPrimitives.ReadInt64LittleEndian(b.Slice(pos, 8));
        pos += 8;
        return v;
    }
}
