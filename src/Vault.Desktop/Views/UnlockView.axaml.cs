using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class UnlockView : UserControl
{
    public UnlockView()
    {
        InitializeComponent();
    }

    private async void OnBrowseClicked(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not UnlockViewModel vm) return;

        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel is null) return;

        var fileType = new FilePickerFileType("Vault file")
        {
            Patterns = ["*.vault"],
            MimeTypes = ["application/octet-stream"],
        };

        var existingFiles = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open vault",
            FileTypeFilter = [fileType],
            AllowMultiple = false,
        });

        if (existingFiles.Count > 0)
        {
            vm.VaultPath = existingFiles[0].Path.LocalPath;
            return;
        }

        // No existing file picked — offer create flow.
        var save = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Create new vault",
            FileTypeChoices = [fileType],
            DefaultExtension = "vault",
            SuggestedFileName = "my.vault",
        });
        if (save is not null) vm.VaultPath = save.Path.LocalPath;
    }
}
