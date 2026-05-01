using Avalonia.Controls;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class ConfirmDialog : Window
{
    public ConfirmDialog()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is ConfirmDialogViewModel vm)
                vm.CloseRequested += (_, result) => Close(result);
        };
    }
}
