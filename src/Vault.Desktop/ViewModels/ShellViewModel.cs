using CommunityToolkit.Mvvm.ComponentModel;
using Vault.Core;
using Vault.Desktop.Services;

namespace Vault.Desktop.ViewModels;

public sealed partial class ShellViewModel : ViewModelBase
{
    private readonly AppSettings _settings;
    private readonly SessionService _sessionService;
    private readonly ClipboardService _clipboard;
    private readonly FailedAttemptLog _failedAttempts;
    private readonly IdleDetector _idle;
    private readonly BackgroundSyncService _backgroundSync;

    [ObservableProperty]
    private ViewModelBase _currentPage;

    [ObservableProperty]
    private string? _globalStatus;

    public ShellViewModel(
        AppSettings settings,
        SessionService sessionService,
        ClipboardService clipboard,
        FailedAttemptLog failedAttempts,
        IdleDetector idle,
        BackgroundSyncService backgroundSync)
    {
        _settings = settings;
        _sessionService = sessionService;
        _clipboard = clipboard;
        _failedAttempts = failedAttempts;
        _idle = idle;
        _backgroundSync = backgroundSync;

        _sessionService.SessionChanged += OnSessionChanged;
        _idle.IdleTimeoutReached += OnIdleTimeout;
        _idle.Start();

        _currentPage = BuildUnlockPage();
    }

    private void OnSessionChanged(object? sender, EventArgs e)
    {
        if (CurrentPage is IDisposable disposable && CurrentPage is not UnlockViewModel)
            disposable.Dispose();

        if (_sessionService.IsUnlocked)
        {
            CurrentPage = new VaultViewModel(
                _sessionService,
                _clipboard,
                onLock: () => _sessionService.Lock());
        }
        else
        {
            _clipboard.CancelPendingClear();
            CurrentPage = BuildUnlockPage();
        }
    }

    private void OnIdleTimeout(object? sender, EventArgs e)
    {
        if (_sessionService.IsUnlocked) _sessionService.Lock();
    }

    public void NoteUserActivity() => _idle.NoteActivity();

    public VaultSession? GetCurrentSession() => _sessionService.Current;

    public SettingsViewModel BuildSettingsViewModel()
    {
        var vm = new SettingsViewModel(_settings);
        if (_backgroundSync.LastSyncAttempt is { } when_)
        {
            vm.LastBackgroundSyncStatus =
                $"{when_.ToLocalTime():HH:mm:ss} — {_backgroundSync.LastSyncResult}";
        }
        return vm;
    }

    public string? CurrentVaultPath => _settings.LastVaultPath;

    public BackgroundSyncService BackgroundSync => _backgroundSync;

    public AppSettings Settings => _settings;

    public void PublishStatus(string message) => GlobalStatus = message;

    private UnlockViewModel BuildUnlockPage()
    {
        var vm = new UnlockViewModel(_settings, _sessionService, _failedAttempts);
        vm.Unlocked += OnUnlocked;
        return vm;
    }

    private void OnUnlocked(object? sender, UnlockedEventArgs e)
    {
        if (!_settings.BackgroundSyncEnabled) return;
        try
        {
            _backgroundSync.Enable(e.VaultPath, e.MasterPassword, e.SecretKey, _settings.BackgroundSyncInterval);
            PublishStatus($"Background sync enabled (every {_settings.BackgroundSyncIntervalMinutes} min).");
        }
        catch (Exception ex)
        {
            PublishStatus($"Could not start background sync: {ex.Message}");
        }
    }
}
