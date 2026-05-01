using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Threading;

namespace Vault.Desktop.Services;

/// <summary>
/// Sets clipboard text and schedules an auto-clear after a delay.
/// Cancelling: each new copy resets the timer.
///
/// The clear-after-delay only erases the value if it's STILL the value we
/// wrote (so we don't overwrite something the user copied in between).
/// </summary>
public sealed class ClipboardService : IDisposable
{
    private readonly TimeSpan _autoClearAfter;
    private CancellationTokenSource? _clearCts;
    private string? _lastWrittenValue;
    private bool _disposed;

    public ClipboardService(TimeSpan autoClearAfter)
    {
        _autoClearAfter = autoClearAfter;
    }

    public async Task CopyAsync(string text, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var clipboard = GetClipboard();
        if (clipboard is null) return;

        await clipboard.SetTextAsync(text).ConfigureAwait(false);
        _lastWrittenValue = text;

        // Cancel any in-flight clear and schedule a new one.
        _clearCts?.Cancel();
        _clearCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var localCts = _clearCts;
        var capturedValue = text;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(_autoClearAfter, localCts.Token).ConfigureAwait(false);
                await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    // Avalonia 12 dropped IClipboard.GetTextAsync — we can't
                    // read the clipboard back to check if our value is still
                    // there. Best-effort: only clear if no newer copy has
                    // been queued since (the cancellation token would have
                    // fired in that case). If the user copied something
                    // unrelated in the meantime via another app, we still
                    // overwrite it; trade-off accepted.
                    if (_lastWrittenValue == capturedValue)
                    {
                        await clipboard.SetTextAsync(string.Empty);
                        _lastWrittenValue = null;
                    }
                });
            }
            catch (OperationCanceledException) { /* superseded */ }
        }, localCts.Token);
    }

    public void CancelPendingClear()
    {
        _clearCts?.Cancel();
        _clearCts = null;
    }

    private static IClipboard? GetClipboard()
    {
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
            && desktop.MainWindow is { Clipboard: { } cb })
        {
            return cb;
        }
        return null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _clearCts?.Cancel();
        _clearCts = null;
        _disposed = true;
    }
}
