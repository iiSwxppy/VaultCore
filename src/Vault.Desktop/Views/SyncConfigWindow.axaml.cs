using Avalonia.Controls;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class SyncConfigWindow : Window
{
    public SyncConfigWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is SyncConfigViewModel vm)
                vm.CloseRequested += (_, _) => Close();
        };
    }
}
