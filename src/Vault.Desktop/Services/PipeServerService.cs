using System.IO.Pipes;
using Vault.Core;
using Vault.Core.Audit;
using Vault.Core.Items;
using Vault.Crypto;
using Vault.Ipc;

namespace Vault.Desktop.Services;

/// <summary>
/// Hosts a named pipe server that listens for IPC requests from the native
/// messaging host. Replies based on the currently-unlocked session.
///
/// One client connection at a time is fine — requests arrive at human pace.
/// We accept one connection, handle one request, send response, close. The
/// extension reconnects per request.
///
/// Pipe permissions: on Windows the default ACL allows only the current user.
/// On Linux .NET creates the pipe in $XDG_RUNTIME_DIR (or /tmp) with 0600
/// file mode, also user-only. Good enough for a personal vault.
///
/// All operations require an unlocked session. If locked, returns ok=false.
/// </summary>
public sealed class PipeServerService : IDisposable
{
    private readonly SessionService _sessionService;
    private CancellationTokenSource? _cts;
    private Task? _runner;
    private bool _disposed;

    public PipeServerService(SessionService sessionService)
    {
        _sessionService = sessionService;
    }

    public void Start()
    {
        if (_runner is not null) return;
        _cts = new CancellationTokenSource();
        _runner = Task.Run(() => RunAsync(_cts.Token));
    }

    private async Task RunAsync(CancellationToken ct)
    {
        var pipeName = DesktopPipe.GetPipeName();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);

                try
                {
                    var req = await DesktopPipe.ReadRequestAsync(server, ct).ConfigureAwait(false);
                    if (req is null) continue;

                    var resp = HandleRequest(req);
                    resp.Id = req.Id;
                    await DesktopPipe.WriteAsync(server, resp, ct).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Per-connection failure: close pipe and accept next.
                    try { server.Disconnect(); } catch { /* ignore */ }
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                // Avoid tight loops if the pipe creation itself fails.
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
        }
    }

    private IpcResponse HandleRequest(IpcRequest req)
    {
        var session = _sessionService.Current;

        // Status query is allowed without an unlocked session.
        if (req.Type == IpcMessageTypes.Status)
        {
            return new IpcResponse { Ok = true, Unlocked = session is not null };
        }

        if (session is null)
        {
            return new IpcResponse { Ok = false, Unlocked = false, Error = "Vault is locked." };
        }

        return req.Type switch
        {
            IpcMessageTypes.FindCredentials => HandleFindCredentials(session, req),
            IpcMessageTypes.GetTotp => HandleGetTotp(session, req),
            IpcMessageTypes.AddCredential => HandleAddCredential(session, req),
            _ => new IpcResponse { Ok = false, Error = $"Unknown message type: {req.Type}" },
        };
    }

    private static IpcResponse HandleFindCredentials(VaultSession session, IpcRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Url))
            return new IpcResponse { Ok = false, Error = "Missing url" };

        var queryHost = PublicSuffix.ExtractHost(req.Url);
        if (queryHost is null)
            return new IpcResponse { Ok = false, Error = "Could not parse url" };
        var queryRegistrable = PublicSuffix.GetRegistrableDomain(queryHost);
        if (queryRegistrable is null)
            return new IpcResponse { Ok = false, Error = "Could not derive registrable domain" };

        var matches = new List<CredentialMatch>();
        foreach (var item in session.Items.Where(i => i.Type == ItemType.Login))
        {
            LoginPayload login;
            try { login = (LoginPayload)session.DecryptItem(item.Id); }
            catch { continue; }

            foreach (var url in login.Urls)
            {
                var itemHost = PublicSuffix.ExtractHost(url);
                if (itemHost is null) continue;
                var itemReg = PublicSuffix.GetRegistrableDomain(itemHost);
                if (itemReg is null) continue;
                if (string.Equals(itemReg, queryRegistrable, StringComparison.Ordinal))
                {
                    matches.Add(new CredentialMatch
                    {
                        ItemId = item.Id.ToString(),
                        Title = login.Title,
                        Username = login.Username,
                        Password = login.Password,
                        HasTotp = !string.IsNullOrEmpty(login.TotpSecret),
                    });
                    break; // one match per item
                }
            }
        }

        // Audit autofill so the user sees in the log when credentials were
        // pulled by the extension. We log once per call, not per item, to
        // avoid flooding.
        if (matches.Count > 0)
        {
            session.AppendAudit(
                AuditAction.ItemDecrypted,
                itemId: null,
                details: $"autofill request for {queryRegistrable}, {matches.Count} match(es)");
        }

        return new IpcResponse { Ok = true, Unlocked = true, Credentials = matches };
    }

    private static IpcResponse HandleGetTotp(VaultSession session, IpcRequest req)
    {
        // Re-use the url field as the item id — keeps the contract simple,
        // saves a separate field on a request type that's only consumed
        // internally. We could split if other clients show up.
        if (string.IsNullOrWhiteSpace(req.Url) || !Guid.TryParse(req.Url, out var id))
            return new IpcResponse { Ok = false, Error = "Missing or invalid item id" };

        try
        {
            var login = (LoginPayload)session.DecryptItem(id);
            if (string.IsNullOrEmpty(login.TotpSecret))
                return new IpcResponse { Ok = false, Error = "Item has no TOTP secret" };
            var bytes = Base32.Decode(login.TotpSecret);
            try
            {
                var now = DateTimeOffset.UtcNow;
                return new IpcResponse
                {
                    Ok = true,
                    Unlocked = true,
                    TotpCode = Totp.Generate(bytes, now),
                    TotpRemainingSeconds = Totp.SecondsUntilNext(now),
                };
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (Exception ex)
        {
            return new IpcResponse { Ok = false, Error = ex.Message };
        }
    }

    private static IpcResponse HandleAddCredential(VaultSession session, IpcRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Url))
            return new IpcResponse { Ok = false, Error = "Missing url" };
        if (string.IsNullOrEmpty(req.Password))
            return new IpcResponse { Ok = false, Error = "Missing password" };

        var host = PublicSuffix.ExtractHost(req.Url) ?? "(unknown)";
        var title = string.IsNullOrWhiteSpace(req.Title) ? host : req.Title!;

        var payload = new LoginPayload
        {
            Title = title,
            Username = string.IsNullOrEmpty(req.Username) ? null : req.Username,
            Password = req.Password,
            Urls = [req.Url],
        };

        try
        {
            session.AddItem(payload);
            return new IpcResponse { Ok = true, Unlocked = true };
        }
        catch (Exception ex)
        {
            return new IpcResponse { Ok = false, Error = ex.Message };
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _cts?.Cancel();
        try { _runner?.Wait(TimeSpan.FromSeconds(2)); } catch { /* ignore */ }
        _cts?.Dispose();
        _disposed = true;
    }
}
