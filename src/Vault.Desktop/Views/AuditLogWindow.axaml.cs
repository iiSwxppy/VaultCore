using Avalonia.Controls;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class AuditLogWindow : Window
{
    public AuditLogWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is AuditLogViewModel vm)
                vm.CloseRequested += (_, _) => Close();
        };
    }
}
