using Avalonia.Controls;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class SyncPromptWindow : Window
{
    public SyncPromptWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is SyncPromptViewModel vm)
                vm.CloseRequested += (_, _) => Close();
        };
    }
}
