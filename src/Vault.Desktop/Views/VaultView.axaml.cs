using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class VaultView : UserControl
{
    public VaultView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (DataContext is not VaultViewModel vm) return;

        vm.AddEditRequested += OnAddEditRequested;
        vm.ConfirmRequested += OnConfirmRequested;
        vm.AuditLogRequested += OnAuditLogRequested;
        vm.SettingsRequested += OnSettingsRequested;
        vm.SyncRequested += OnSyncRequested;
        vm.ConfigureSyncRequested += OnConfigureSyncRequested;
    }

    private static Window? GetParentWindow(Visual self)
    {
        if (TopLevel.GetTopLevel(self) is Window w) return w;
        if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d)
            return d.MainWindow;
        return null;
    }

    private async void OnAddEditRequested(object? sender, AddEditRequest req)
    {
        var parent = GetParentWindow(this);
        if (parent is null) return;

        var dlgVm = new AddEditLoginViewModel(req.Existing);
        var dlg = new AddEditLoginWindow { DataContext = dlgVm };
        var result = await dlg.ShowDialog<Vault.Core.Items.LoginPayload?>(parent);
        req.OnSave(result);
    }

    private async void OnConfirmRequested(object? sender, ConfirmRequest req)
    {
        var parent = GetParentWindow(this);
        if (parent is null) { req.OnResult(false); return; }

        var dlgVm = new ConfirmDialogViewModel(
            title: req.Title,
            message: req.Message,
            confirmLabel: req.ConfirmLabel,
            isDestructive: req.IsDestructive);
        var dlg = new ConfirmDialog { DataContext = dlgVm };
        var result = await dlg.ShowDialog<bool>(parent);
        req.OnResult(result);
    }

    private async void OnAuditLogRequested(object? sender, EventArgs e)
    {
        var parent = GetParentWindow(this);
        if (parent?.DataContext is not ShellViewModel shell) return;
        var session = shell.GetCurrentSession();
        if (session is null) return;

        var auditVm = new AuditLogViewModel(session);
        var dlg = new AuditLogWindow { DataContext = auditVm };
        await dlg.ShowDialog(parent);
    }

    private async void OnSettingsRequested(object? sender, EventArgs e)
    {
        var parent = GetParentWindow(this);
        if (parent?.DataContext is not ShellViewModel shell) return;

        var settingsVm = shell.BuildSettingsViewModel();
        var dlg = new SettingsWindow { DataContext = settingsVm };
        await dlg.ShowDialog<bool>(parent);
    }

    private async void OnSyncRequested(object? sender, ViewModels.SyncRequest req)
    {
        var parent = GetParentWindow(this);
        if (parent?.DataContext is not ShellViewModel shell) return;
        var session = shell.GetCurrentSession();
        var vaultPath = shell.CurrentVaultPath;
        if (session is null || string.IsNullOrEmpty(vaultPath))
        {
            req.SetStatus("Sync needs an unlocked vault.");
            return;
        }

        var orch = new Vault.Sync.SyncOrchestrator(vaultPath);
        if (!orch.HasConfig)
        {
            var configVm = new SyncConfigViewModel(vaultPath);
            var configDlg = new SyncConfigWindow { DataContext = configVm };
            await configDlg.ShowDialog(parent);
            if (!configVm.Saved)
            {
                req.SetStatus("Sync remote not configured.");
                return;
            }
        }

        // Prompt for password + secret key.
        var promptVm = new SyncPromptViewModel();
        var dlg = new SyncPromptWindow { DataContext = promptVm };
        await dlg.ShowDialog(parent);
        if (!promptVm.Confirmed)
        {
            req.SetStatus("Sync cancelled.");
            return;
        }

        var pwdBytes = System.Text.Encoding.UTF8.GetBytes(promptVm.Password);
        var sk = promptVm.SecretKey;
        try
        {
            req.SetStatus("Syncing...");
            var result = await Task.Run(() => orch.SyncAsync(session, pwdBytes, sk).GetAwaiter().GetResult());

            switch (result.Outcome)
            {
                case Vault.Sync.SyncOutcome.PushedFresh:
                    req.SetStatus($"First sync complete. ETag {result.ETag[..Math.Min(8, result.ETag.Length)]}.");
                    break;
                case Vault.Sync.SyncOutcome.PushedNoMerge:
                    req.SetStatus("Pushed (remote was up to date).");
                    break;
                case Vault.Sync.SyncOutcome.Merged:
                    var m = result.MergeResult!;
                    req.SetStatus(
                        $"Merged: +{m.RemoteOnly} new, {m.LocalUpdated} updated, " +
                        $"{m.RemoteItemsDroppedByTombstone + m.LocalItemsDroppedByTombstone} deletions propagated, " +
                        $"{m.Resurrections} resurrections.");
                    break;
            }
        }
        catch (Exception ex)
        {
            req.SetStatus($"Sync failed: {ex.Message}");
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(pwdBytes);
        }
    }

    private async void OnConfigureSyncRequested(object? sender, EventArgs e)
    {
        var parent = GetParentWindow(this);
        if (parent?.DataContext is not ShellViewModel shell) return;
        var vaultPath = shell.CurrentVaultPath;
        if (string.IsNullOrEmpty(vaultPath)) return;

        var vm = new SyncConfigViewModel(vaultPath);
        var dlg = new SyncConfigWindow { DataContext = vm };
        await dlg.ShowDialog(parent);
        if (vm.Saved && DataContext is VaultViewModel vvm)
        {
            // Use the public Markstatus path through a sync request — easiest reuse.
            // Just log locally:
            shell.PublishStatus("Sync remote saved.");
        }
    }
}
