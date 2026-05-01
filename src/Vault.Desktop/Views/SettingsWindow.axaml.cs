using Avalonia.Controls;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class SettingsWindow : Window
{
    public SettingsWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is SettingsViewModel vm)
                vm.CloseRequested += (_, saved) => Close(saved);
        };
    }
}
