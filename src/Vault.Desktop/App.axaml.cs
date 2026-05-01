using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Vault.Desktop.Services;
using Vault.Desktop.ViewModels;
using Vault.Desktop.Views;

namespace Vault.Desktop;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var settings = AppSettings.LoadOrDefault();
            var sessionService = new SessionService();
            var clipboard = new ClipboardService(autoClearAfter: settings.ClipboardClearAfter);
            var failedAttempts = new FailedAttemptLog();
            var idleDetector = new IdleDetector(idleThreshold: settings.AutoLockTimeout);
            var pipeServer = new PipeServerService(sessionService);
            pipeServer.Start();

            // Status reporting goes through the shell so the bottom status bar reflects it.
            ShellViewModel? shellRef = null;
            var bgSync = new BackgroundSyncService(
                sessionService,
                statusReporter: msg => Avalonia.Threading.Dispatcher.UIThread.Post(
                    () => shellRef?.PublishStatus(msg)));

            shellRef = new ShellViewModel(
                settings, sessionService, clipboard, failedAttempts, idleDetector, bgSync);

            desktop.MainWindow = new MainWindow { DataContext = shellRef };

            desktop.ShutdownRequested += (_, _) =>
            {
                bgSync.Dispose();
                pipeServer.Dispose();
                clipboard.Dispose();
                idleDetector.Dispose();
                sessionService.Dispose();
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
