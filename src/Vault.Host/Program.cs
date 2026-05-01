using System.IO.Pipes;
using System.Security.Principal;
using Vault.Ipc;

namespace Vault.Host;

/// <summary>
/// Native messaging host: a thin proxy between the browser extension and the
/// desktop app.
///
/// Lifecycle:
///   - Started by the browser when the extension calls chrome.runtime.connectNative.
///   - Reads framed JSON requests from stdin.
///   - For each request: opens the desktop named pipe, forwards request, reads
///     response, writes back to stdout.
///   - Loops until stdin EOF (extension disconnected).
///
/// Stays stateless. Has no keys, no vault data. Cannot answer anything if the
/// desktop app isn't running or the vault isn't unlocked — returns ok=false.
///
/// The host runs without a console; logging goes to stderr only when --debug
/// is passed (Chrome captures stderr to the extension's host log).
/// </summary>
internal static class Program
{
    private static bool s_debug;
    private static readonly TimeSpan PipeConnectTimeout = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan PerRequestTimeout = TimeSpan.FromSeconds(5);

    private static async Task<int> Main(string[] args)
    {
        s_debug = args.Contains("--debug");
        Log("native host started");

        // Browser-supplied first argument is the extension origin (Chrome) or
        // extension id (Firefox). We log it for diagnosis but don't enforce —
        // the manifest's `allowed_origins` already gates which extensions can
        // launch us.
        if (args.Length > 0 && args[0].StartsWith("chrome-extension://", StringComparison.Ordinal))
            Log($"caller: {args[0]}");

        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();

        try
        {
            while (true)
            {
                IpcRequest? req;
                try
                {
                    req = await NativeMessagingFraming.ReadAsync(stdin).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Log($"read error: {ex.Message}");
                    return 1;
                }
                if (req is null) { Log("stdin EOF"); return 0; }

                var resp = await ForwardToDesktopAsync(req).ConfigureAwait(false);
                resp.Id = req.Id;

                try
                {
                    await NativeMessagingFraming.WriteAsync(stdout, resp).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Log($"write error: {ex.Message}");
                    return 1;
                }
            }
        }
        catch (Exception ex)
        {
            Log($"fatal: {ex.Message}");
            return 1;
        }
    }

    private static async Task<IpcResponse> ForwardToDesktopAsync(IpcRequest req)
    {
        using var cts = new CancellationTokenSource(PerRequestTimeout);

        try
        {
            using var pipe = new NamedPipeClientStream(
                serverName: ".",
                pipeName: DesktopPipe.GetPipeName(),
                direction: PipeDirection.InOut,
                options: PipeOptions.Asynchronous);

            // Bounded connect: if the desktop isn't running we want to fail
            // fast, not hang the extension.
            try
            {
                await pipe.ConnectAsync(PipeConnectTimeout, cts.Token).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                return new IpcResponse
                {
                    Ok = false,
                    Unlocked = false,
                    Error = "Desktop app is not running or vault is not unlocked.",
                };
            }

            await DesktopPipe.WriteAsync(pipe, req, cts.Token).ConfigureAwait(false);
            var response = await DesktopPipe.ReadResponseAsync(pipe, cts.Token).ConfigureAwait(false);
            return response ?? new IpcResponse { Ok = false, Error = "Empty response from desktop." };
        }
        catch (OperationCanceledException)
        {
            return new IpcResponse { Ok = false, Error = "Desktop did not respond in time." };
        }
        catch (Exception ex)
        {
            Log($"forward error: {ex.Message}");
            return new IpcResponse { Ok = false, Error = "IPC failure." };
        }
    }

    private static void Log(string message)
    {
        if (!s_debug) return;
        try { Console.Error.WriteLine($"[vault-mh] {DateTimeOffset.UtcNow:O} {message}"); }
        catch { /* swallow — never crash the host on logging */ }
    }
}
