using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;

namespace Vault.Ipc;

/// <summary>
/// Named pipe used between the native messaging host and the desktop app.
///
/// Same framing as native messaging (4-byte LE length + JSON payload) so we
/// can reuse the same parser. Single round-trip per connection: extension
/// asks once, gets one response, pipe closes. Keeps logic trivial — desktop
/// doesn't need to track per-connection state.
///
/// Pipe name on Windows: \\.\pipe\vaultcore-{username}
/// On Linux/macOS we use a Unix socket at $XDG_RUNTIME_DIR/vaultcore.sock
/// (handled by .NET's NamedPipe* classes which abstract this on POSIX).
/// </summary>
public static class DesktopPipe
{
    public static string GetPipeName()
    {
        var user = Environment.UserName.ToLowerInvariant();
        // .NET pipe names are case-sensitive on Linux but not Windows; lowercase keeps both happy.
        return $"vaultcore-{user}";
    }

    public static async Task WriteAsync(Stream pipe, IpcRequest request, CancellationToken ct = default)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(request, IpcJsonContext.Default.IpcRequest);
        var lenBuf = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, json.Length);
        await pipe.WriteAsync(lenBuf, ct).ConfigureAwait(false);
        await pipe.WriteAsync(json, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task WriteAsync(Stream pipe, IpcResponse response, CancellationToken ct = default)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(response, IpcJsonContext.Default.IpcResponse);
        var lenBuf = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lenBuf, json.Length);
        await pipe.WriteAsync(lenBuf, ct).ConfigureAwait(false);
        await pipe.WriteAsync(json, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<IpcRequest?> ReadRequestAsync(Stream pipe, CancellationToken ct = default)
    {
        var lenBuf = new byte[4];
        if (!await ReadExactAsync(pipe, lenBuf, ct).ConfigureAwait(false)) return null;
        var len = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
        if (len is <= 0 or > 1024 * 1024) throw new InvalidDataException("Bad message length");
        var payload = new byte[len];
        if (!await ReadExactAsync(pipe, payload, ct).ConfigureAwait(false))
            throw new EndOfStreamException();
        return JsonSerializer.Deserialize(payload, IpcJsonContext.Default.IpcRequest);
    }

    public static async Task<IpcResponse?> ReadResponseAsync(Stream pipe, CancellationToken ct = default)
    {
        var lenBuf = new byte[4];
        if (!await ReadExactAsync(pipe, lenBuf, ct).ConfigureAwait(false)) return null;
        var len = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
        if (len is <= 0 or > 1024 * 1024) throw new InvalidDataException("Bad message length");
        var payload = new byte[len];
        if (!await ReadExactAsync(pipe, payload, ct).ConfigureAwait(false))
            throw new EndOfStreamException();
        return JsonSerializer.Deserialize(payload, IpcJsonContext.Default.IpcResponse);
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
