using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Vault.Desktop.ViewModels;

/// <summary>
/// Prompt the user to re-enter the master password + secret key so we can
/// decrypt a possibly-divergent remote during sync. The password is held
/// only for the duration of the sync call, then zeroed.
/// </summary>
public sealed partial class SyncPromptViewModel : ViewModelBase
{
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConfirmCommand))]
    private string _password = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConfirmCommand))]
    private string _secretKey = "";

    [ObservableProperty]
    private string? _statusMessage;

    public bool Confirmed { get; private set; }

    public event EventHandler? CloseRequested;

    [RelayCommand(CanExecute = nameof(CanConfirm))]
    private void Confirm()
    {
        Confirmed = true;
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }

    private bool CanConfirm() => !string.IsNullOrEmpty(Password) && !string.IsNullOrEmpty(SecretKey);

    [RelayCommand]
    private void Cancel()
    {
        Confirmed = false;
        Password = "";
        SecretKey = "";
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }
}
