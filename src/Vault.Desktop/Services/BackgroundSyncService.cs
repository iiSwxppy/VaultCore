using Avalonia.Threading;
using Vault.Core;
using Vault.Crypto;
using Vault.Sync;

namespace Vault.Desktop.Services;

/// <summary>
/// Optional background sync. Holds a copy of the master password + secret key
/// in memory for the duration of the session, runs sync on:
///   - A timer (default every 5 minutes)
///   - Local vault file changes detected by FileSystemWatcher (debounced 30s)
///
/// Trade-off: enabling background sync keeps credentials in process memory
/// for the whole session. That's a worse posture than the default (credentials
/// only briefly during unlock). Off by default; user opts in via settings.
///
/// On lock or app shutdown, credentials are zeroed and watchers stopped.
/// </summary>
public sealed class BackgroundSyncService : IDisposable
{
    private readonly SessionService _sessionService;
    private readonly Action<string> _statusReporter;

    private SecureBytes? _masterPassword;
    private string? _secretKey;
    private string? _vaultPath;

    private DispatcherTimer? _intervalTimer;
    private FileSystemWatcher? _watcher;
    private CancellationTokenSource? _watcherDebounceCts;

    private TimeSpan _interval = TimeSpan.FromMinutes(5);
    private bool _enabled;
    private bool _running;
    private DateTimeOffset? _lastSyncAttempt;
    private string? _lastSyncResult;

    private bool _disposed;

    public BackgroundSyncService(SessionService sessionService, Action<string> statusReporter)
    {
        _sessionService = sessionService;
        _statusReporter = statusReporter;
        _sessionService.SessionChanged += OnSessionChanged;
    }

    public bool IsEnabled => _enabled;
    public DateTimeOffset? LastSyncAttempt => _lastSyncAttempt;
    public string? LastSyncResult => _lastSyncResult;

    /// <summary>
    /// Enable background sync for this session. Credentials are copied into
    /// SecureBytes (zeroed on disable / dispose).
    /// </summary>
    public void Enable(string vaultPath, ReadOnlySpan<byte> masterPassword, string secretKey, TimeSpan interval)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Disable(); // start clean

        _vaultPath = vaultPath;
        _masterPassword = new SecureBytes(masterPassword);
        _secretKey = secretKey;
        _interval = interval < TimeSpan.FromMinutes(1) ? TimeSpan.FromMinutes(1) : interval;
        _enabled = true;

        _intervalTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = _interval };
        _intervalTimer.Tick += async (_, _) => await TrySyncAsync(reason: "interval");
        _intervalTimer.Start();

        SetupWatcher(vaultPath);
    }

    public void Disable()
    {
        _intervalTimer?.Stop();
        _intervalTimer = null;
        _watcher?.Dispose();
        _watcher = null;
        _watcherDebounceCts?.Cancel();
        _watcherDebounceCts = null;

        _masterPassword?.Dispose();
        _masterPassword = null;
        _secretKey = null;
        _vaultPath = null;
        _enabled = false;
    }

    private void OnSessionChanged(object? sender, EventArgs e)
    {
        // Lock event = always disable. Unlock requires explicit Enable() call —
        // we don't have credentials at unlock time without prompting.
        if (!_sessionService.IsUnlocked)
        {
            Disable();
        }
    }

    private void SetupWatcher(string vaultPath)
    {
        var dir = Path.GetDirectoryName(vaultPath);
        var name = Path.GetFileName(vaultPath);
        if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(name)) return;

        try
        {
            _watcher = new FileSystemWatcher(dir, name)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                EnableRaisingEvents = true,
            };
            _watcher.Changed += OnWatcherEvent;
            _watcher.Created += OnWatcherEvent;
            _watcher.Renamed += OnWatcherEvent;
        }
        catch
        {
            // Some platforms (network shares, certain mounts) reject watchers.
            // Falling back to interval-only is acceptable.
            _watcher = null;
        }
    }

    private async void OnWatcherEvent(object? sender, FileSystemEventArgs e)
    {
        // Debounce: writes during a save come in bursts. Wait 30s of quiet
        // before triggering sync.
        _watcherDebounceCts?.Cancel();
        _watcherDebounceCts = new CancellationTokenSource();
        var token = _watcherDebounceCts.Token;
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(30), token).ConfigureAwait(false);
            await TrySyncAsync(reason: "file-changed").ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* superseded */ }
    }

    private async Task TrySyncAsync(string reason)
    {
        if (!_enabled || _running) return;
        var session = _sessionService.Current;
        if (session is null) return;
        if (_masterPassword is null || _secretKey is null || _vaultPath is null) return;

        _running = true;
        try
        {
            var orch = new SyncOrchestrator(_vaultPath);
            if (!orch.HasConfig)
            {
                _lastSyncResult = "no remote configured";
                _statusReporter($"Background sync skipped: {_lastSyncResult}");
                return;
            }

            _statusReporter($"Background sync ({reason})...");
            var pwdBytes = _masterPassword.ToArray();
            try
            {
                var result = await Task.Run(() =>
                    orch.SyncAsync(session, pwdBytes, _secretKey).GetAwaiter().GetResult()).ConfigureAwait(false);

                _lastSyncAttempt = DateTimeOffset.UtcNow;
                _lastSyncResult = result.Outcome switch
                {
                    SyncOutcome.PushedFresh => "first push",
                    SyncOutcome.PushedNoMerge => "pushed (no remote changes)",
                    SyncOutcome.Merged => $"merged: +{result.MergeResult!.RemoteOnly} new, " +
                        $"{result.MergeResult.RemoteItemsDroppedByTombstone + result.MergeResult.LocalItemsDroppedByTombstone} deletions",
                    _ => "ok",
                };
                _statusReporter($"Background sync: {_lastSyncResult}");
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(pwdBytes);
            }
        }
        catch (Exception ex)
        {
            _lastSyncAttempt = DateTimeOffset.UtcNow;
            _lastSyncResult = $"error: {ex.Message}";
            _statusReporter($"Background sync failed: {ex.Message}");
        }
        finally
        {
            _running = false;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _sessionService.SessionChanged -= OnSessionChanged;
        Disable();
        _disposed = true;
    }
}
