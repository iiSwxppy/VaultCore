using System.Security.Cryptography;

namespace Vault.Crypto;

/// <summary>
/// A byte buffer that zeroes its contents when disposed.
/// Use for secret material (keys, passwords, plaintext payloads).
/// Not a security boundary — memory can still be paged or dumped.
/// Just reduces the window where secrets sit in heap.
/// </summary>
public sealed class SecureBytes : IDisposable
{
    private byte[]? _buffer;
    private bool _disposed;

    public int Length => _buffer?.Length ?? 0;

    public SecureBytes(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        _buffer = GC.AllocateUninitializedArray<byte>(length, pinned: true);
    }

    public SecureBytes(ReadOnlySpan<byte> source)
    {
        _buffer = GC.AllocateUninitializedArray<byte>(source.Length, pinned: true);
        source.CopyTo(_buffer);
    }

    public Span<byte> AsSpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _buffer.AsSpan();
    }

    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _buffer.AsSpan();
    }

    public byte[] ToArray()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _buffer!.ToArray();
    }

    public static SecureBytes FromUtf8(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var byteCount = System.Text.Encoding.UTF8.GetByteCount(value);
        var result = new SecureBytes(byteCount);
        System.Text.Encoding.UTF8.GetBytes(value, result.AsSpan());
        return result;
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (_buffer is not null)
        {
            CryptographicOperations.ZeroMemory(_buffer);
            _buffer = null;
        }
        _disposed = true;
    }
}
