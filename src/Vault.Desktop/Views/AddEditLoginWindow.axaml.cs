using Avalonia.Controls;
using Vault.Core.Items;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class AddEditLoginWindow : Window
{
    public AddEditLoginWindow()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (DataContext is AddEditLoginViewModel vm)
        {
            vm.CloseRequested += (_, payload) => Close(payload);
        }
    }
}
