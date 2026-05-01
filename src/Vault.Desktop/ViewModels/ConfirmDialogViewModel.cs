using CommunityToolkit.Mvvm.Input;

namespace Vault.Desktop.ViewModels;

public sealed partial class ConfirmDialogViewModel : ViewModelBase
{
    public string Title { get; }
    public string Message { get; }
    public string ConfirmLabel { get; }
    public string CancelLabel { get; }
    public bool IsDestructive { get; }
    public bool? Result { get; private set; }

    public event EventHandler<bool>? CloseRequested;

    public ConfirmDialogViewModel(
        string title,
        string message,
        string confirmLabel = "Confirm",
        string cancelLabel = "Cancel",
        bool isDestructive = false)
    {
        Title = title;
        Message = message;
        ConfirmLabel = confirmLabel;
        CancelLabel = cancelLabel;
        IsDestructive = isDestructive;
    }

    [RelayCommand]
    private void Confirm()
    {
        Result = true;
        CloseRequested?.Invoke(this, true);
    }

    [RelayCommand]
    private void Cancel()
    {
        Result = false;
        CloseRequested?.Invoke(this, false);
    }
}
