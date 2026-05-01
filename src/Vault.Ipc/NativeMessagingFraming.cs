using System.Buffers.Binary;
using System.Text.Json;

namespace Vault.Ipc;

/// <summary>
/// Chrome native messaging protocol framing:
///   - 4-byte little-endian length prefix
///   - UTF-8 JSON payload of that length
///
/// Spec: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
///
/// Max message size: 1 MiB browser→host, 64 KiB host→browser. We enforce both
/// to avoid being terminated mid-message by the browser on oversized output.
/// </summary>
public static class NativeMessagingFraming
{
    public const int MaxBrowserToHost = 1024 * 1024;
    public const int MaxHostToBrowser = 64 * 1024;

    public static async Task<IpcRequest?> ReadAsync(Stream stdin, CancellationToken ct = default)
    {
        var lenBuf = new byte[4];
        if (!await ReadExactAsync(stdin, lenBuf, ct).ConfigureAwait(false))
            return null; // EOF — browser closed the pipe

        var length = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
        if (length is <= 0 or > MaxBrowserToHost)
            throw new InvalidDataException($"Native message length out of bounds: {length}");

        var payload = new byte[length];
        if (!await ReadExactAsync(stdin, payload, ct).ConfigureAwait(false))
            throw new EndOfStreamException("Truncated native message");

        return JsonSerializer.Deserialize(payload, IpcJsonContext.Default.IpcRequest);
    }

    public static async Task WriteAsync(Stream stdout, IpcResponse response, CancellationToken ct = default)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(response, IpcJsonContext.Default.IpcResponse);
        if (json.Length > MaxHostToBrowser)
            throw new InvalidOperationException($"Response too large for native messaging: {json.Length}");

        var lenBuf = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, json.Length);

        await stdout.WriteAsync(lenBuf, ct).ConfigureAwait(false);
        await stdout.WriteAsync(json, ct).ConfigureAwait(false);
        await stdout.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer[read..], ct).ConfigureAwait(false);
            if (n == 0) return false;
            read += n;
        }
        return true;
    }
}
