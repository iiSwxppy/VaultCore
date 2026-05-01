using Vault.Core;

namespace Vault.Desktop.Services;

/// <summary>
/// Owns the currently unlocked VaultSession, if any. Exposes events when the
/// session changes so view models can react (lock/unlock UI swaps).
/// </summary>
public sealed class SessionService : IDisposable
{
    private VaultSession? _session;
    private bool _disposed;

    public VaultSession? Current
    {
        get { ObjectDisposedException.ThrowIf(_disposed, this); return _session; }
    }

    public bool IsUnlocked => _session is not null;

    public event EventHandler? SessionChanged;

    public void Set(VaultSession? session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var old = _session;
        _session = session;
        old?.Dispose();
        SessionChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Lock() => Set(null);

    public void Dispose()
    {
        if (_disposed) return;
        _session?.Dispose();
        _session = null;
        _disposed = true;
    }
}
