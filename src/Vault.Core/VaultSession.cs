using System.Security.Cryptography;
using System.Text.Json;
using Vault.Core.Audit;
using Vault.Core.Items;
using Vault.Core.Serialization;
using Vault.Crypto;

namespace Vault.Core;

/// <summary>
/// In-memory representation of an unlocked vault. Holds VaultKey for the lifetime
/// of the session. Dispose to wipe keys.
/// </summary>
public sealed class VaultSession : IDisposable
{
    private static readonly byte[] AukVerifierPlaintext = "vault-verify-v1"u8.ToArray();
    private static readonly byte[] AukVerifierAd = AesGcmAead.BuildAssociatedData(1, "auk-verify"u8);
    private static readonly byte[] VaultKeyAd = AesGcmAead.BuildAssociatedData(1, "vault-key-wrap"u8);
    private static readonly byte[] HmacKeyInfo = "vault-hmac-v1"u8.ToArray();
    private static readonly byte[] AuditKeyInfo = "vault-audit-v1"u8.ToArray();
    private static readonly byte[] ItemKeyInfoPrefix = "vault-item-v1\0"u8.ToArray();

    private readonly string _path;
    private SecureBytes _vaultKey;
    private SecureBytes _hmacKey;
    private SecureBytes _auditKey;
    private VaultManifest _manifest;
    private readonly Dictionary<Guid, VaultFile.EncryptedItem> _items;
    private readonly List<VaultFile.EncryptedAuditEntry> _auditEntries;
    private readonly Dictionary<Guid, Tombstone> _tombstones;
    private bool _disposed;

    private VaultSession(
        string path,
        VaultManifest manifest,
        SecureBytes vaultKey,
        SecureBytes hmacKey,
        SecureBytes auditKey,
        IEnumerable<VaultFile.EncryptedItem> items,
        IEnumerable<VaultFile.EncryptedAuditEntry> auditEntries,
        IEnumerable<Tombstone> tombstones)
    {
        _path = path;
        _manifest = manifest;
        _vaultKey = vaultKey;
        _hmacKey = hmacKey;
        _auditKey = auditKey;
        _items = items.ToDictionary(i => i.Id);
        _auditEntries = auditEntries.ToList();
        _tombstones = tombstones.ToDictionary(t => t.ItemId);
    }

    public IReadOnlyCollection<VaultFile.EncryptedItem> Items
    {
        get { ThrowIfDisposed(); return _items.Values; }
    }

    public VaultManifest Manifest
    {
        get { ThrowIfDisposed(); return _manifest; }
    }

    public int AuditEntryCount
    {
        get { ThrowIfDisposed(); return _auditEntries.Count; }
    }

    public IReadOnlyCollection<Tombstone> Tombstones
    {
        get { ThrowIfDisposed(); return _tombstones.Values; }
    }

    public IReadOnlyList<VaultFile.EncryptedAuditEntry> AuditEntriesEncrypted
    {
        get { ThrowIfDisposed(); return _auditEntries; }
    }

    public byte[] VaultKeyFingerprint()
    {
        ThrowIfDisposed();
        using var fp = Hkdf.DeriveKey(_vaultKey.AsReadOnlySpan(), 16, info: "vault-fingerprint-v1"u8);
        return fp.ToArray();
    }

    public static VaultSession Create(
        string path,
        ReadOnlySpan<byte> masterPassword,
        string secretKey,
        Argon2Kdf.Params? kdfParams = null)
    {
        if (!SecretKey.TryParse(secretKey, out var normalizedSecretKey))
            throw new ArgumentException("Invalid secret key format", nameof(secretKey));

        kdfParams ??= Argon2Kdf.Params.Default;

        var accountId = RandomBytes.AccountId();
        var kdfSalt = RandomBytes.Salt();

        using var muk = Argon2Kdf.Derive(
            masterPassword, kdfSalt, kdfParams, outputLength: 32, associatedData: accountId);

        var secretKeyBytes = SecretKey.ToBytes(normalizedSecretKey);
        using var auk = Hkdf.Combine2SKD(muk.AsReadOnlySpan(), secretKeyBytes, accountId);

        using var vaultKey = new SecureBytes(RandomBytes.Get(32));
        var vaultKeyEnvelope = AesGcmAead.Encrypt(auk.AsReadOnlySpan(), vaultKey.AsReadOnlySpan(), VaultKeyAd);
        var verifierEnvelope = AesGcmAead.Encrypt(auk.AsReadOnlySpan(), AukVerifierPlaintext, AukVerifierAd);

        var manifest = new VaultManifest
        {
            FormatVersion = 1,
            AccountId = Hex.ToHex(accountId),
            KdfSaltHex = Hex.ToHex(kdfSalt),
            Argon2MemoryKib = kdfParams.MemoryKib,
            Argon2Iterations = kdfParams.Iterations,
            Argon2Parallelism = kdfParams.Parallelism,
            AukVerifierEnvelopeHex = Hex.ToHex(verifierEnvelope),
            VaultKeyEnvelopeHex = Hex.ToHex(vaultKeyEnvelope),
        };

        var hmacKey = Hkdf.DeriveKey(vaultKey.AsReadOnlySpan(), 32, info: HmacKeyInfo);
        var auditKey = Hkdf.DeriveKey(vaultKey.AsReadOnlySpan(), 32, info: AuditKeyInfo);

        var session = new VaultSession(
            path, manifest,
            new SecureBytes(vaultKey.AsReadOnlySpan()),
            hmacKey, auditKey,
            [], [], []);

        session.AppendAuditInternal(AuditAction.VaultCreated, null, null);
        session.Save();
        return session;
    }

    public static VaultSession Unlock(
        string path,
        ReadOnlySpan<byte> masterPassword,
        string secretKey)
    {
        if (!SecretKey.TryParse(secretKey, out var normalizedSecretKey))
            throw new ArgumentException("Invalid secret key format", nameof(secretKey));

        VaultManifest manifest;
        byte[] accountId, kdfSalt, verifierEnvelope, vaultKeyEnvelope;
        Argon2Kdf.Params kdfParams;
        try
        {
            manifest = ReadManifestUnverified(path);
            accountId = Hex.FromHex(manifest.AccountId);
            kdfSalt = Hex.FromHex(manifest.KdfSaltHex);
            verifierEnvelope = Hex.FromHex(manifest.AukVerifierEnvelopeHex);
            vaultKeyEnvelope = Hex.FromHex(manifest.VaultKeyEnvelopeHex);
            kdfParams = new Argon2Kdf.Params(
                manifest.Argon2MemoryKib, manifest.Argon2Iterations, manifest.Argon2Parallelism);
            kdfParams.Validate();
        }
        catch (Exception ex) when (ex is FormatException
            or InvalidDataException
            or System.Text.Json.JsonException
            or ArgumentException)
        {
            throw new CryptographicException("Vault file is corrupt or tampered.", ex);
        }

        using var muk = Argon2Kdf.Derive(masterPassword, kdfSalt, kdfParams, 32, associatedData: accountId);
        var secretKeyBytes = SecretKey.ToBytes(normalizedSecretKey);
        using var auk = Hkdf.Combine2SKD(muk.AsReadOnlySpan(), secretKeyBytes, accountId);

        SecureBytes verifier;
        try
        {
            verifier = AesGcmAead.Decrypt(auk.AsReadOnlySpan(), verifierEnvelope, AukVerifierAd);
        }
        catch (CryptographicException)
        {
            throw new InvalidPasswordException("Master password or secret key is incorrect.");
        }
        verifier.Dispose();

        var vaultKey = AesGcmAead.Decrypt(auk.AsReadOnlySpan(), vaultKeyEnvelope, VaultKeyAd);
        var hmacKey = Hkdf.DeriveKey(vaultKey.AsReadOnlySpan(), 32, info: HmacKeyInfo);
        var auditKey = Hkdf.DeriveKey(vaultKey.AsReadOnlySpan(), 32, info: AuditKeyInfo);

        var contents = VaultFile.Read(path, hmacKey.AsReadOnlySpan());

        var session = new VaultSession(
            path, contents.Manifest, vaultKey, hmacKey, auditKey,
            contents.Items, contents.AuditEntries, contents.Tombstones);

        session.AppendAuditInternal(AuditAction.VaultUnlocked, null, null);
        session.Save();
        return session;
    }

    public static (VaultManifest Manifest, IReadOnlyList<VaultFile.EncryptedItem> Items, IReadOnlyList<VaultFile.EncryptedAuditEntry> Audit, IReadOnlyList<Tombstone> Tombstones, SecureBytes VaultKey, byte[] VaultKeyFingerprint)
        DecryptBuffer(byte[] buffer, ReadOnlySpan<byte> masterPassword, string secretKey)
    {
        if (!SecretKey.TryParse(secretKey, out var normalizedSecretKey))
            throw new ArgumentException("Invalid secret key format", nameof(secretKey));

        var pos = 0;
        if (buffer.Length < 12) throw new InvalidDataException("Buffer too short");
        if (!buffer.AsSpan(0, 4).SequenceEqual(VaultFile.Magic)) throw new InvalidDataException("Bad magic");
        pos += 4;
        var version = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos, 4));
        pos += 4;
        if (version is < 1 or > 3) throw new InvalidDataException($"Unsupported version {version}");
        var mLen = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(pos, 4));
        pos += 4;
        var manifestJson = buffer.AsSpan(pos, mLen);
        var manifest = JsonSerializer.Deserialize(manifestJson, VaultJsonContext.Default.VaultManifest)
            ?? throw new InvalidDataException("Bad manifest");

        var accountId = Hex.FromHex(manifest.AccountId);
        var kdfSalt = Hex.FromHex(manifest.KdfSaltHex);
        var verifierEnvelope = Hex.FromHex(manifest.AukVerifierEnvelopeHex);
        var vaultKeyEnvelope = Hex.FromHex(manifest.VaultKeyEnvelopeHex);
        var kdfParams = new Argon2Kdf.Params(
            manifest.Argon2MemoryKib, manifest.Argon2Iterations, manifest.Argon2Parallelism);
        kdfParams.Validate();

        using var muk = Argon2Kdf.Derive(masterPassword, kdfSalt, kdfParams, 32, associatedData: accountId);
        var secretKeyBytes = SecretKey.ToBytes(normalizedSecretKey);
        using var auk = Hkdf.Combine2SKD(muk.AsReadOnlySpan(), secretKeyBytes, accountId);

        SecureBytes verifier;
        try
        {
            verifier = AesGcmAead.Decrypt(auk.AsReadOnlySpan(), verifierEnvelope, AukVerifierAd);
        }
        catch (CryptographicException)
        {
            throw new InvalidPasswordException("Master password or secret key is incorrect for the buffer.");
        }
        verifier.Dispose();

        var vaultKey = AesGcmAead.Decrypt(auk.AsReadOnlySpan(), vaultKeyEnvelope, VaultKeyAd);
        using var hmacKey = Hkdf.DeriveKey(vaultKey.AsReadOnlySpan(), 32, info: HmacKeyInfo);

        var contents = VaultFile.ReadFromBytes(buffer, hmacKey.AsReadOnlySpan());

        using var fpKey = Hkdf.DeriveKey(vaultKey.AsReadOnlySpan(), 16, info: "vault-fingerprint-v1"u8);
        var fingerprint = fpKey.ToArray();

        return (contents.Manifest, contents.Items, contents.AuditEntries, contents.Tombstones, vaultKey, fingerprint);
    }

    public Guid AddItem(ItemPayload payload)
    {
        ThrowIfDisposed();
        var id = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var type = MapType(payload);

        var json = JsonSerializer.SerializeToUtf8Bytes(payload, VaultJsonContext.Default.ItemPayload);
        var ad = VaultFile.ItemAssociatedData(id, type, now, now);

        using var itemKey = DeriveItemKey(id);
        var envelope = AesGcmAead.Encrypt(itemKey.AsReadOnlySpan(), json, ad);
        CryptographicOperations.ZeroMemory(json);

        _items[id] = new VaultFile.EncryptedItem(id, type, now, now, envelope);
        // New UUID, no tombstone collision possible.
        AppendAuditInternal(AuditAction.ItemCreated, id, $"type={type}");
        Save();
        return id;
    }

    public void UpdateItem(Guid id, ItemPayload payload)
    {
        ThrowIfDisposed();
        if (!_items.TryGetValue(id, out var existing))
            throw new KeyNotFoundException($"Item {id} not found");

        var type = MapType(payload);
        var now = DateTimeOffset.UtcNow;
        var json = JsonSerializer.SerializeToUtf8Bytes(payload, VaultJsonContext.Default.ItemPayload);
        var ad = VaultFile.ItemAssociatedData(id, type, existing.CreatedAt, now);

        using var itemKey = DeriveItemKey(id);
        var envelope = AesGcmAead.Encrypt(itemKey.AsReadOnlySpan(), json, ad);
        CryptographicOperations.ZeroMemory(json);

        _items[id] = existing with { Type = type, UpdatedAt = now, Envelope = envelope };
        AppendAuditInternal(AuditAction.ItemUpdated, id, null);
        Save();
    }

    public bool DeleteItem(Guid id)
    {
        ThrowIfDisposed();
        var removed = _items.Remove(id);
        if (removed)
        {
            // Record a tombstone so the deletion propagates via sync.
            // Use UtcNow as DeletedAt — must be > existing.UpdatedAt for the
            // merger to drop the item on remote. UtcNow always satisfies this
            // because UpdatedAt was set at most "now" and we just removed it.
            _tombstones[id] = new Tombstone(id, DateTimeOffset.UtcNow);
            AppendAuditInternal(AuditAction.ItemDeleted, id, null);
            Save();
        }
        return removed;
    }

    /// <summary>
    /// Prune tombstones older than the given age. CAUTION: pruning is unsafe
    /// if any device hasn't synced past the deletion timestamp — it will
    /// resurrect deleted items on next sync from that device.
    /// Returns the number of tombstones removed.
    /// </summary>
    public int PruneTombstones(TimeSpan olderThan)
    {
        ThrowIfDisposed();
        var cutoff = DateTimeOffset.UtcNow - olderThan;
        var toRemove = _tombstones.Values.Where(t => t.DeletedAt < cutoff).Select(t => t.ItemId).ToList();
        foreach (var id in toRemove) _tombstones.Remove(id);
        if (toRemove.Count > 0)
        {
            AppendAuditInternal(AuditAction.MaintenancePerformed, null,
                $"pruned {toRemove.Count} tombstone(s) older than {olderThan.TotalDays:F0} days");
            Save();
        }
        return toRemove.Count;
    }

    public void ChangeMasterPassword(
        ReadOnlySpan<byte> newMasterPassword,
        string secretKey,
        Argon2Kdf.Params? newKdfParams = null)
    {
        ThrowIfDisposed();

        if (!SecretKey.TryParse(secretKey, out var normalizedSecretKey))
            throw new ArgumentException("Invalid secret key format", nameof(secretKey));

        newKdfParams ??= new Argon2Kdf.Params(
            _manifest.Argon2MemoryKib, _manifest.Argon2Iterations, _manifest.Argon2Parallelism);

        var accountId = Hex.FromHex(_manifest.AccountId);
        var newKdfSalt = RandomBytes.Salt();

        using var newMuk = Argon2Kdf.Derive(
            newMasterPassword, newKdfSalt, newKdfParams, 32, associatedData: accountId);
        var secretKeyBytes = SecretKey.ToBytes(normalizedSecretKey);
        using var newAuk = Hkdf.Combine2SKD(newMuk.AsReadOnlySpan(), secretKeyBytes, accountId);

        var newVerifierEnvelope = AesGcmAead.Encrypt(newAuk.AsReadOnlySpan(), AukVerifierPlaintext, AukVerifierAd);
        var newVaultKeyEnvelope = AesGcmAead.Encrypt(newAuk.AsReadOnlySpan(), _vaultKey.AsReadOnlySpan(), VaultKeyAd);

        _manifest = _manifest with
        {
            KdfSaltHex = Hex.ToHex(newKdfSalt),
            Argon2MemoryKib = newKdfParams.MemoryKib,
            Argon2Iterations = newKdfParams.Iterations,
            Argon2Parallelism = newKdfParams.Parallelism,
            AukVerifierEnvelopeHex = Hex.ToHex(newVerifierEnvelope),
            VaultKeyEnvelopeHex = Hex.ToHex(newVaultKeyEnvelope),
            UpdatedAt = DateTimeOffset.UtcNow,
        };

        AppendAuditInternal(AuditAction.MasterPasswordChanged, null, null);
        Save();
    }

    public ItemPayload DecryptItem(Guid id, bool logAccess = false)
    {
        ThrowIfDisposed();
        if (!_items.TryGetValue(id, out var item))
            throw new KeyNotFoundException($"Item {id} not found");

        var ad = VaultFile.ItemAssociatedData(item.Id, item.Type, item.CreatedAt, item.UpdatedAt);
        using var itemKey = DeriveItemKey(item.Id);
        using var plain = AesGcmAead.Decrypt(itemKey.AsReadOnlySpan(), item.Envelope, ad);
        var payload = JsonSerializer.Deserialize(plain.AsReadOnlySpan(), VaultJsonContext.Default.ItemPayload)
            ?? throw new InvalidDataException("Empty item payload");

        if (logAccess)
        {
            AppendAuditInternal(AuditAction.ItemDecrypted, id, null);
            Save();
        }
        return payload;
    }

    public void AppendAudit(AuditAction action, Guid? itemId = null, string? details = null)
    {
        ThrowIfDisposed();
        AppendAuditInternal(action, itemId, details);
        Save();
    }

    public IReadOnlyList<AuditEntry> GetAuditLog()
    {
        ThrowIfDisposed();
        var result = new List<AuditEntry>(_auditEntries.Count);
        foreach (var encrypted in _auditEntries)
        {
            var ad = VaultFile.AuditAssociatedData(encrypted.Timestamp);
            using var plain = AesGcmAead.Decrypt(_auditKey.AsReadOnlySpan(), encrypted.Envelope, ad);
            var entry = JsonSerializer.Deserialize(plain.AsReadOnlySpan(), VaultJsonContext.Default.AuditEntry)
                ?? throw new InvalidDataException("Bad audit entry");
            result.Add(entry);
        }
        return result;
    }

    public int TruncateAuditLog(int keepCount)
    {
        ThrowIfDisposed();
        ArgumentOutOfRangeException.ThrowIfNegative(keepCount);
        if (_auditEntries.Count <= keepCount) return 0;
        var toRemove = _auditEntries.Count - keepCount;
        _auditEntries.RemoveRange(0, toRemove);
        Save();
        return toRemove;
    }

    /// <summary>
    /// Replace local items, audit entries, and tombstones wholesale, then save.
    /// Used by the sync merge layer.
    /// </summary>
    public void ReplaceItemsAuditAndTombstones(
        IEnumerable<VaultFile.EncryptedItem> items,
        IEnumerable<VaultFile.EncryptedAuditEntry> auditEntries,
        IEnumerable<Tombstone> tombstones)
    {
        ThrowIfDisposed();
        _items.Clear();
        foreach (var i in items) _items[i.Id] = i;
        _auditEntries.Clear();
        _auditEntries.AddRange(auditEntries);
        _tombstones.Clear();
        foreach (var t in tombstones) _tombstones[t.ItemId] = t;
        Save();
    }

    private void AppendAuditInternal(AuditAction action, Guid? itemId, string? details)
    {
        var entry = new AuditEntry(DateTimeOffset.UtcNow, action, itemId, details);
        var json = JsonSerializer.SerializeToUtf8Bytes(entry, VaultJsonContext.Default.AuditEntry);
        var ad = VaultFile.AuditAssociatedData(entry.Timestamp);
        var envelope = AesGcmAead.Encrypt(_auditKey.AsReadOnlySpan(), json, ad);
        CryptographicOperations.ZeroMemory(json);
        _auditEntries.Add(new VaultFile.EncryptedAuditEntry(entry.Timestamp, envelope));
    }

    private SecureBytes DeriveItemKey(Guid id)
    {
        Span<byte> info = stackalloc byte[ItemKeyInfoPrefix.Length + 16];
        ItemKeyInfoPrefix.AsSpan().CopyTo(info);
        if (!id.TryWriteBytes(info[ItemKeyInfoPrefix.Length..])) throw new InvalidOperationException();
        return Hkdf.DeriveKey(_vaultKey.AsReadOnlySpan(), 32, info: info);
    }

    private void Save()
    {
        VaultFile.Write(
            _path, _manifest,
            _items.Values.ToList(),
            _auditEntries,
            _tombstones.Values.ToList(),
            _hmacKey.AsReadOnlySpan());
    }

    private static ItemType MapType(ItemPayload p) => p switch
    {
        LoginPayload => ItemType.Login,
        SecureNotePayload => ItemType.SecureNote,
        CreditCardPayload => ItemType.CreditCard,
        IdentityPayload => ItemType.Identity,
        SshKeyPayload => ItemType.SshKey,
        TotpSeedPayload => ItemType.TotpSeed,
        _ => throw new ArgumentException($"Unknown payload type {p.GetType().Name}"),
    };

    private static VaultManifest ReadManifestUnverified(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Span<byte> hdr = stackalloc byte[4 + 4 + 4];
        if (fs.Read(hdr) != hdr.Length) throw new InvalidDataException("Vault file too short");

        if (!hdr[..4].SequenceEqual(VaultFile.Magic)) throw new InvalidDataException("Bad magic");
        var version = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(hdr[4..8]);
        if (version is < 1 or > 3) throw new InvalidDataException($"Unsupported version {version}");
        var mLen = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(hdr[8..12]);

        var json = new byte[mLen];
        if (fs.Read(json) != mLen) throw new InvalidDataException("Manifest read short");
        return JsonSerializer.Deserialize(json, VaultJsonContext.Default.VaultManifest)
            ?? throw new InvalidDataException("Bad manifest");
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    public void Dispose()
    {
        if (_disposed) return;
        _vaultKey.Dispose();
        _hmacKey.Dispose();
        _auditKey.Dispose();
        _disposed = true;
    }
}

public sealed class InvalidPasswordException(string message) : Exception(message);
