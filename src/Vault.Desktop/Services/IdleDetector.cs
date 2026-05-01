using Avalonia.Threading;

namespace Vault.Desktop.Services;

/// <summary>
/// App-level idle detector. Resets on every NoteActivity() call.
/// Views wire NoteActivity to mouse/keyboard events on the main window.
///
/// This is intentionally NOT system-wide idle detection. System-wide would
/// require platform-specific code (GetLastInputInfo on Windows). For a
/// password manager, app-level idle is the right semantic anyway: lock when
/// the user steps away from THIS app, regardless of what they're doing
/// elsewhere.
/// </summary>
public sealed class IdleDetector : IDisposable
{
    private readonly TimeSpan _idleThreshold;
    private DispatcherTimer? _timer;
    private DateTime _lastActivity;
    private bool _disposed;

    public event EventHandler? IdleTimeoutReached;

    public IdleDetector(TimeSpan idleThreshold)
    {
        _idleThreshold = idleThreshold;
        _lastActivity = DateTime.UtcNow;
    }

    /// <summary>Start polling for idle. Call after the UI is up.</summary>
    public void Start()
    {
        if (_timer is not null) return;
        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(15),
        };
        _timer.Tick += (_, _) =>
        {
            if (DateTime.UtcNow - _lastActivity >= _idleThreshold)
            {
                IdleTimeoutReached?.Invoke(this, EventArgs.Empty);
                // Reset timer so we don't re-fire continuously after lock.
                _lastActivity = DateTime.UtcNow;
            }
        };
        _timer.Start();
    }

    public void Stop()
    {
        _timer?.Stop();
        _timer = null;
    }

    public void NoteActivity()
    {
        _lastActivity = DateTime.UtcNow;
    }

    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _disposed = true;
    }
}
