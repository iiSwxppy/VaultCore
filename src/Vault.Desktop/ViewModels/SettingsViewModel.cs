using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Vault.Desktop.ViewModels;

public sealed partial class SettingsViewModel : ViewModelBase
{
    private readonly AppSettings _settings;

    [ObservableProperty]
    private int _autoLockMinutes;

    [ObservableProperty]
    private int _clipboardClearSeconds;

    [ObservableProperty]
    private string _lastVaultPath = "";

    [ObservableProperty]
    private bool _backgroundSyncEnabled;

    [ObservableProperty]
    private int _backgroundSyncIntervalMinutes;

    [ObservableProperty]
    private string _lastBackgroundSyncStatus = "(never)";

    public event EventHandler<bool>? CloseRequested;

    public SettingsViewModel(AppSettings settings)
    {
        _settings = settings;
        _autoLockMinutes = settings.AutoLockMinutes;
        _clipboardClearSeconds = settings.ClipboardClearSeconds;
        _lastVaultPath = settings.LastVaultPath ?? "";
        _backgroundSyncEnabled = settings.BackgroundSyncEnabled;
        _backgroundSyncIntervalMinutes = settings.BackgroundSyncIntervalMinutes;
    }

    [RelayCommand]
    private void Save()
    {
        _settings.AutoLockMinutes = Math.Clamp(AutoLockMinutes, 1, 240);
        _settings.ClipboardClearSeconds = Math.Clamp(ClipboardClearSeconds, 5, 600);
        _settings.LastVaultPath = string.IsNullOrWhiteSpace(LastVaultPath) ? null : LastVaultPath;
        _settings.BackgroundSyncEnabled = BackgroundSyncEnabled;
        _settings.BackgroundSyncIntervalMinutes = Math.Clamp(BackgroundSyncIntervalMinutes, 1, 1440);
        _settings.Save();
        CloseRequested?.Invoke(this, true);
    }

    [RelayCommand]
    private void Cancel() => CloseRequested?.Invoke(this, false);
}
