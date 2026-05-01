using Vault.Core;
using Vault.Core.Audit;
using Vault.Core.Export;
using Vault.Core.Import;
using Vault.Core.Items;
using Vault.Crypto;
using Vault.Sync;

namespace Vault.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            return args switch
            {
                ["init", var path] => CmdInit(path),
                ["unlock", var path] => CmdUnlock(path),
                ["list", var path] => CmdList(path),
                ["search", var path, var query] => CmdSearch(path, query),
                ["find-url", var path, var url] => CmdFindUrl(path, url),
                ["get", var path, var id] => CmdGet(path, id),
                ["add-login", var path] => CmdAddLogin(path),
                ["delete", var path, var id] => CmdDelete(path, id),
                ["change-password", var path] => CmdChangePassword(path),
                ["import-bitwarden", var path, var src] => CmdImportBitwarden(path, src),
                ["import-1pux", var path, var src] => CmdImport1pux(path, src),
                ["import-keepass-xml", var path, var src] => CmdImportKeePassXml(path, src),
                ["export-encrypted", var path, var dst] => CmdExportEncrypted(path, dst),
                ["export-plaintext", var path, var dst] => CmdExportPlaintext(path, dst),
                ["audit", var path] => CmdAudit(path, limit: 50),
                ["audit", var path, "--all"] => CmdAudit(path, limit: int.MaxValue),
                ["audit-truncate", var path, var keep] => CmdAuditTruncate(path, keep),
                ["tombstone-list", var path] => CmdTombstoneList(path),
                ["tombstone-prune", var path, var days] => CmdTombstonePrune(path, days),
                ["sync-configure", var path] => CmdSyncConfigure(path),
                ["sync", var path] => CmdSync(path, quiet: false),
                ["sync", var path, "--quiet"] => CmdSync(path, quiet: true),
                ["sync-status", var path] => CmdSyncStatus(path),
                ["genpass", ..] => CmdGenPass(args),
                ["totp", var b32] => CmdTotp(b32),
                ["check-pwned", ..] => CmdCheckPwned(),
                _ => PrintUsage(),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static int PrintUsage()
    {
        Console.Error.WriteLine("""
            vault — personal password vault

            Usage:
              vault init <path>                       Create a new vault
              vault unlock <path>                     Verify password (test unlock)
              vault list <path>                       List item titles
              vault search <path> <query>             Search items by title/username/url
              vault find-url <path> <url>             Find logins matching a URL (eTLD+1)
              vault get <path> <id>                   Show one item (decrypted, logged)
              vault add-login <path>                  Add a login interactively
              vault delete <path> <id>                Delete an item
              vault change-password <path>            Rotate master password
              vault import-bitwarden <path> <file>    Import Bitwarden JSON export
              vault import-1pux <path> <file>         Import 1Password .1pux archive
              vault import-keepass-xml <path> <file>  Import KeePass 2.x XML export
              vault export-encrypted <path> <out>     Backup vault (still encrypted)
              vault export-plaintext <path> <out>     DANGEROUS: dump everything as JSON
              vault audit <path> [--all]              Show audit log (last 50, or all)
              vault audit-truncate <path> <keep>      Drop all but most recent N entries
              vault tombstone-list <path>             Show pending deletes
              vault tombstone-prune <path> <days>     Drop tombstones older than N days (UNSAFE if any device unsynced)
              vault sync-configure <path>             Set up S3-compatible remote
              vault sync <path>                       Pull, merge, and push
              vault sync-status <path>                Show last-known sync state
              vault genpass [--len N] [--no-symbols]
              vault totp <base32-secret>              Print current TOTP code
              vault check-pwned                       Check a password against HIBP
            """);
        return 64;
    }

    private static int CmdInit(string path)
    {
        if (File.Exists(path))
        {
            Console.Error.WriteLine($"refusing to overwrite existing file: {path}");
            return 1;
        }

        Console.Error.WriteLine("Creating new vault.");
        Console.Error.WriteLine("Choose a strong master password (long, memorable).");
        var pwdString = ConsolePassword.ReadConfirmedPassword("Master password: ");
        using var pwd = SecureBytes.FromUtf8(pwdString);

        var secretKey = SecretKey.Generate();
        Console.Error.WriteLine();
        Console.Error.WriteLine("=== SECRET KEY — WRITE THIS DOWN SOMEWHERE SAFE ===");
        Console.Error.WriteLine($"  {secretKey}");
        Console.Error.WriteLine("Without this AND your master password, the vault cannot be unlocked.");
        Console.Error.WriteLine("Anthropic / Claude / no one can recover it.");
        Console.Error.WriteLine("====================================================");
        Console.Error.WriteLine();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var session = VaultSession.Create(path, pwd.AsReadOnlySpan(), secretKey);
        sw.Stop();
        Console.Error.WriteLine($"Vault created at {path} (KDF took {sw.ElapsedMilliseconds}ms)");
        return 0;
    }

    private static int CmdUnlock(string path)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var session = OpenSession(path);
        sw.Stop();
        Console.Error.WriteLine($"Unlocked in {sw.ElapsedMilliseconds}ms. {session.Items.Count} item(s).");
        return 0;
    }

    private static int CmdList(string path)
    {
        using var session = OpenSession(path);
        Console.WriteLine($"{"ID",-36}  {"TYPE",-12}  TITLE");
        foreach (var item in session.Items.OrderBy(i => i.UpdatedAt))
        {
            // Title is encrypted; we have to decrypt to show it. For listing,
            // some apps store a plaintext title. We chose maximum confidentiality.
            var payload = session.DecryptItem(item.Id);
            Console.WriteLine($"{item.Id}  {item.Type,-12}  {payload.Title}");
        }
        return 0;
    }

    private static int CmdGet(string path, string idStr)
    {
        if (!Guid.TryParse(idStr, out var id)) { Console.Error.WriteLine("invalid id"); return 1; }
        using var session = OpenSession(path);
        var payload = session.DecryptItem(id, logAccess: true);
        switch (payload)
        {
            case LoginPayload l:
                Console.WriteLine($"Title:    {l.Title}");
                Console.WriteLine($"Username: {l.Username}");
                Console.WriteLine($"Password: {l.Password}");
                if (l.Urls.Count > 0) Console.WriteLine($"URLs:     {string.Join(", ", l.Urls)}");
                if (!string.IsNullOrEmpty(l.TotpSecret))
                {
                    var code = Totp.Generate(Base32.Decode(l.TotpSecret), DateTimeOffset.UtcNow);
                    var remaining = Totp.SecondsUntilNext(DateTimeOffset.UtcNow);
                    Console.WriteLine($"TOTP:     {code} (expires in {remaining}s)");
                }
                if (!string.IsNullOrEmpty(l.Notes)) Console.WriteLine($"Notes:    {l.Notes}");
                break;
            default:
                Console.WriteLine($"[{payload.GetType().Name}]");
                Console.WriteLine($"Title: {payload.Title}");
                if (!string.IsNullOrEmpty(payload.Notes)) Console.WriteLine($"Notes: {payload.Notes}");
                break;
        }
        return 0;
    }

    private static int CmdSearch(string path, string query)
    {
        using var session = OpenSession(path);
        var q = query.ToLowerInvariant();
        var matches = 0;

        Console.WriteLine($"{"ID",-36}  {"TYPE",-12}  TITLE");
        foreach (var item in session.Items.OrderBy(i => i.UpdatedAt))
        {
            var payload = session.DecryptItem(item.Id);
            var hit =
                payload.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                (payload is LoginPayload login && (
                    (login.Username?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    login.Urls.Any(u => u.Contains(q, StringComparison.OrdinalIgnoreCase))));

            if (hit)
            {
                Console.WriteLine($"{item.Id}  {item.Type,-12}  {payload.Title}");
                matches++;
            }
        }
        Console.Error.WriteLine($"{matches} match(es)");
        return matches > 0 ? 0 : 1;
    }

    private static int CmdFindUrl(string path, string url)
    {
        using var session = OpenSession(path);
        var queryHost = ExtractHost(url);
        if (string.IsNullOrEmpty(queryHost))
        {
            Console.Error.WriteLine("could not extract host from URL");
            return 1;
        }

        var matches = 0;
        foreach (var item in session.Items.Where(i => i.Type == ItemType.Login))
        {
            var login = (LoginPayload)session.DecryptItem(item.Id);
            foreach (var u in login.Urls)
            {
                var itemHost = ExtractHost(u);
                if (string.IsNullOrEmpty(itemHost)) continue;
                if (HostsMatch(itemHost, queryHost))
                {
                    Console.WriteLine($"{item.Id}  {login.Title}  ({login.Username})");
                    matches++;
                    break;
                }
            }
        }
        Console.Error.WriteLine($"{matches} match(es) for host '{queryHost}'");
        return matches > 0 ? 0 : 1;
    }

    private static string? ExtractHost(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        var s = url.Trim();
        if (!s.Contains("://", StringComparison.Ordinal)) s = "https://" + s;
        if (!Uri.TryCreate(s, UriKind.Absolute, out var uri)) return null;
        return uri.Host.ToLowerInvariant();
    }

    /// <summary>
    /// Naive registrable-domain match without PSL.
    /// Compares the last 2 labels (e.g., google.com == accounts.google.com).
    /// Misses .co.uk-style suffixes — good enough for CLI; PSL belongs in the
    /// extension where stakes are higher.
    /// </summary>
    private static bool HostsMatch(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
        return Last2Labels(a).Equals(Last2Labels(b), StringComparison.OrdinalIgnoreCase);

        static string Last2Labels(string host)
        {
            var parts = host.Split('.');
            return parts.Length <= 2 ? host : string.Join('.', parts[^2], parts[^1]);
        }
    }

    private static int CmdAudit(string path, int limit)
    {
        using var session = OpenSession(path);
        var entries = session.GetAuditLog();
        var slice = entries.OrderByDescending(e => e.Timestamp).Take(limit).Reverse().ToList();
        Console.WriteLine($"Total entries: {entries.Count}, showing {slice.Count}");
        Console.WriteLine();
        Console.WriteLine($"{"TIMESTAMP",-25}  {"ACTION",-25}  {"ITEM",-36}  DETAILS");
        foreach (var e in slice)
        {
            var ts = e.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture);
            var item = e.ItemId?.ToString() ?? "";
            Console.WriteLine($"{ts,-25}  {e.Action,-25}  {item,-36}  {e.Details}");
        }
        return 0;
    }

    private static int CmdAuditTruncate(string path, string keepStr)
    {
        if (!int.TryParse(keepStr, System.Globalization.CultureInfo.InvariantCulture, out var keep) || keep < 0)
        {
            Console.Error.WriteLine("invalid keep count");
            return 1;
        }
        using var session = OpenSession(path);
        var removed = session.TruncateAuditLog(keep);
        Console.Error.WriteLine($"Removed {removed} oldest audit entries.");
        return 0;
    }

    private static int CmdTombstoneList(string path)
    {
        using var session = OpenSession(path);
        var tombs = session.Tombstones.OrderByDescending(t => t.DeletedAt).ToList();
        if (tombs.Count == 0) { Console.Error.WriteLine("No tombstones."); return 0; }
        foreach (var t in tombs)
        {
            Console.WriteLine($"{t.ItemId}  deleted {t.DeletedAt:yyyy-MM-dd HH:mm:ss zzz}");
        }
        Console.Error.WriteLine($"({tombs.Count} total)");
        return 0;
    }

    private static int CmdTombstonePrune(string path, string daysStr)
    {
        if (!int.TryParse(daysStr, System.Globalization.CultureInfo.InvariantCulture, out var days) || days < 1)
        {
            Console.Error.WriteLine("days must be a positive integer");
            return 1;
        }
        using var session = OpenSession(path);
        var dropped = session.PruneTombstones(TimeSpan.FromDays(days));
        Console.Error.WriteLine($"Pruned {dropped} tombstone(s) older than {days} day(s).");
        if (dropped > 0)
            Console.Error.WriteLine("WARNING: if any device hasn't synced past those deletion timestamps, the items will resurrect on its next sync.");
        return 0;
    }

    private static int CmdAddLogin(string path)
    {
        using var session = OpenSession(path);

        Console.Error.Write("Title: ");    var title = Console.ReadLine() ?? "";
        Console.Error.Write("Username: "); var user = Console.ReadLine() ?? "";
        Console.Error.Write("URL: ");      var url = Console.ReadLine() ?? "";

        Console.Error.Write("Generate password? [Y/n] ");
        var gen = (Console.ReadLine() ?? "").Trim().ToUpperInvariant();
        string password;
        if (gen is "" or "Y" or "YES")
        {
            password = PasswordGenerator.Charset(new PasswordGenerator.CharsetOptions(Length: 24));
            Console.Error.WriteLine($"Generated: {password}");
        }
        else
        {
            using var pwd = ConsolePassword.Read("Password: ");
            password = System.Text.Encoding.UTF8.GetString(pwd.AsReadOnlySpan());
        }

        var item = new LoginPayload
        {
            Title = title,
            Username = string.IsNullOrEmpty(user) ? null : user,
            Password = password,
            Urls = string.IsNullOrEmpty(url) ? [] : [url],
        };
        var id = session.AddItem(item);
        Console.Error.WriteLine($"Added: {id}");
        return 0;
    }

    private static int CmdDelete(string path, string idStr)
    {
        if (!Guid.TryParse(idStr, out var id)) { Console.Error.WriteLine("invalid id"); return 1; }
        using var session = OpenSession(path);
        if (!session.DeleteItem(id)) { Console.Error.WriteLine("not found"); return 1; }
        Console.Error.WriteLine("deleted");
        return 0;
    }

    private static int CmdGenPass(string[] args)
    {
        var len = 20;
        var symbols = true;
        var ambiguous = false;
        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--len" when i + 1 < args.Length: len = int.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture); break;
                case "--no-symbols": symbols = false; break;
                case "--no-ambiguous": ambiguous = true; break;
            }
        }
        var pwd = PasswordGenerator.Charset(new PasswordGenerator.CharsetOptions(
            Length: len, UseSymbols: symbols, ExcludeAmbiguous: ambiguous));
        Console.WriteLine(pwd);
        return 0;
    }

    private static int CmdTotp(string base32Secret)
    {
        var secret = Base32.Decode(base32Secret);
        var code = Totp.Generate(secret, DateTimeOffset.UtcNow);
        var remaining = Totp.SecondsUntilNext(DateTimeOffset.UtcNow);
        Console.WriteLine($"{code}  ({remaining}s)");
        return 0;
    }

    private static int CmdChangePassword(string path)
    {
        Console.Error.WriteLine("Step 1: unlock with current credentials.");
        using var session = OpenSession(path);

        Console.Error.WriteLine();
        Console.Error.WriteLine("Step 2: enter NEW master password.");
        var newPwdString = ConsolePassword.ReadConfirmedPassword("New master password: ");
        using var newPwd = SecureBytes.FromUtf8(newPwdString);

        // Re-prompt for the secret key (we never stored it).
        var sk = Environment.GetEnvironmentVariable("VAULT_SECRET_KEY");
        if (string.IsNullOrEmpty(sk))
        {
            Console.Error.Write("Secret key (same as before): ");
            sk = Console.ReadLine() ?? "";
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        session.ChangeMasterPassword(newPwd.AsReadOnlySpan(), sk);
        sw.Stop();
        Console.Error.WriteLine($"Master password rotated ({sw.ElapsedMilliseconds}ms). Items unchanged.");
        return 0;
    }

    private static int CmdImportBitwarden(string path, string source)
    {
        if (!File.Exists(source)) { Console.Error.WriteLine($"file not found: {source}"); return 1; }
        using var session = OpenSession(path);
        var report = BitwardenImporter.ImportFromFile(source, session);
        session.AppendAudit(AuditAction.ImportPerformed, null, $"bitwarden: {report.Imported}/{report.TotalRead}");
        Console.Error.WriteLine($"Imported {report.Imported}/{report.TotalRead}, skipped {report.Skipped}");
        foreach (var w in report.Warnings) Console.Error.WriteLine($"  warn: {w}");
        return 0;
    }

    private static int CmdImport1pux(string path, string source)
    {
        if (!File.Exists(source)) { Console.Error.WriteLine($"file not found: {source}"); return 1; }
        using var session = OpenSession(path);
        var report = OnePasswordImporter.ImportFromFile(source, session);
        session.AppendAudit(AuditAction.ImportPerformed, null, $"1pux: {report.Imported}/{report.TotalRead}");
        Console.Error.WriteLine($"Imported {report.Imported}/{report.TotalRead}, skipped {report.Skipped}");
        foreach (var w in report.Warnings) Console.Error.WriteLine($"  warn: {w}");
        return 0;
    }

    private static int CmdImportKeePassXml(string path, string source)
    {
        if (!File.Exists(source)) { Console.Error.WriteLine($"file not found: {source}"); return 1; }
        using var session = OpenSession(path);
        var report = KeePassXmlImporter.ImportFromFile(source, session);
        session.AppendAudit(AuditAction.ImportPerformed, null, $"keepass-xml: {report.Imported}/{report.TotalRead}");
        Console.Error.WriteLine($"Imported {report.Imported}/{report.TotalRead}, skipped {report.Skipped}");
        foreach (var w in report.Warnings) Console.Error.WriteLine($"  warn: {w}");
        return 0;
    }

    private static int CmdExportEncrypted(string path, string dst)
    {
        if (!File.Exists(path)) { Console.Error.WriteLine($"vault not found: {path}"); return 1; }

        // Open session first to log the event INSIDE the vault before copying.
        using (var session = OpenSession(path))
        {
            session.AppendAudit(AuditAction.EncryptedBackupExported, null, $"to={dst}");
        }
        // Now the file on disk has the audit entry. Copy it.
        VaultExporter.ExportEncryptedBackup(path, dst);
        Console.Error.WriteLine($"Encrypted backup written to {dst}");
        Console.Error.WriteLine("Restore: open with the same master password + secret key.");
        return 0;
    }

    private static int CmdExportPlaintext(string path, string dst)
    {
        Console.Error.WriteLine("=== WARNING: PLAINTEXT EXPORT ===");
        Console.Error.WriteLine("This writes ALL passwords, TOTP secrets, and notes to disk in cleartext.");
        Console.Error.WriteLine("Anyone who reads the output file gets full access to your accounts.");
        Console.Error.Write("Type 'I UNDERSTAND' to continue: ");
        var c1 = Console.ReadLine();
        if (c1 != "I UNDERSTAND") { Console.Error.WriteLine("aborted"); return 1; }

        Console.Error.Write($"Confirm output path '{dst}' by typing it again: ");
        var c2 = Console.ReadLine();
        if (c2 != dst) { Console.Error.WriteLine("aborted: path mismatch"); return 1; }

        using var session = OpenSession(path);
        session.AppendAudit(AuditAction.PlaintextExported, null, $"to={dst} items={session.Items.Count}");
        VaultExporter.ExportPlaintextJson(session, dst);
        Console.Error.WriteLine($"Plaintext export written to {dst} (file mode set to user-only where supported)");
        return 0;
    }

    private static int CmdCheckPwned()
    {
        using var pwd = ConsolePassword.Read("Password to check (not stored): ");
        var pwdStr = System.Text.Encoding.UTF8.GetString(pwd.AsReadOnlySpan());

        var hibp = new HibpChecker();
        var count = hibp.CheckPasswordAsync(pwdStr).GetAwaiter().GetResult();
        if (count == 0)
        {
            Console.WriteLine("Not found in HIBP. (No guarantee — only that this password hasn't appeared in known breaches.)");
            return 0;
        }
        Console.WriteLine($"PWNED — seen {count:N0} times in known breaches. Do not use.");
        return 2;
    }

    private static int CmdSyncConfigure(string path)
    {
        if (!File.Exists(path)) { Console.Error.WriteLine($"vault not found: {path}"); return 1; }

        Console.Error.WriteLine("Configure S3-compatible remote.");
        Console.Error.Write("Endpoint URL (e.g. https://s3.us-west-002.backblazeb2.com): ");
        var endpoint = (Console.ReadLine() ?? "").Trim();
        Console.Error.Write("Region [us-east-1]: ");
        var region = (Console.ReadLine() ?? "").Trim();
        if (string.IsNullOrEmpty(region)) region = "us-east-1";
        Console.Error.Write("Bucket name: ");
        var bucket = (Console.ReadLine() ?? "").Trim();
        Console.Error.Write("Object key [vault.bin]: ");
        var key = (Console.ReadLine() ?? "").Trim();
        if (string.IsNullOrEmpty(key)) key = "vault.bin";
        Console.Error.Write("Access key ID: ");
        var accessKey = (Console.ReadLine() ?? "").Trim();
        using var secretBuf = ConsolePassword.Read("Secret access key: ");
        var secret = System.Text.Encoding.UTF8.GetString(secretBuf.AsReadOnlySpan());
        Console.Error.Write("Force path style? [Y/n]: ");
        var pathStyleResp = (Console.ReadLine() ?? "Y").Trim().ToUpperInvariant();
        var forcePathStyle = pathStyleResp != "N" && pathStyleResp != "NO";

        var config = new SyncRemoteConfig
        {
            Endpoint = endpoint,
            Region = region,
            Bucket = bucket,
            Key = key,
            AccessKeyId = accessKey,
            SecretAccessKey = secret,
            ForcePathStyle = forcePathStyle,
        };
        var orch = new SyncOrchestrator(path);
        orch.ConfigureRemote(config);
        Console.Error.WriteLine($"Sync state written to {path}.sync");
        return 0;
    }

    private static int CmdSync(string path, bool quiet)
    {
        if (!File.Exists(path)) { if (!quiet) Console.Error.WriteLine($"vault not found: {path}"); return 1; }
        var orch = new SyncOrchestrator(path);
        if (!orch.HasConfig)
        {
            if (!quiet) Console.Error.WriteLine("Sync not configured. Run: vault sync-configure <path>");
            return 1;
        }

        var sk = Environment.GetEnvironmentVariable("VAULT_SECRET_KEY");
        if (string.IsNullOrEmpty(sk))
        {
            if (quiet)
            {
                // Scripted use without env credentials is a hard fail — don't prompt.
                Console.Error.WriteLine("VAULT_SECRET_KEY not set; cannot sync in --quiet mode.");
                return 2;
            }
            Console.Error.Write("Secret key: ");
            sk = Console.ReadLine() ?? "";
        }

        var pwdEnv = Environment.GetEnvironmentVariable("VAULT_MASTER_PASSWORD");
        SecureBytes pwd;
        if (!string.IsNullOrEmpty(pwdEnv))
        {
            pwd = new SecureBytes(System.Text.Encoding.UTF8.GetBytes(pwdEnv));
        }
        else if (quiet)
        {
            Console.Error.WriteLine("VAULT_MASTER_PASSWORD not set; cannot sync in --quiet mode.");
            return 2;
        }
        else
        {
            pwd = ConsolePassword.Read("Master password: ");
        }

        using (pwd)
        using (var session = VaultSession.Unlock(path, pwd.AsReadOnlySpan(), sk))
        {
            try
            {
                if (!quiet) Console.Error.WriteLine("Syncing...");
                var result = orch.SyncAsync(session, pwd.ToArray(), sk).GetAwaiter().GetResult();

                if (quiet)
                {
                    // One-line machine-readable summary.
                    Console.WriteLine($"{result.Outcome} etag={result.ETag}");
                }
                else
                {
                    switch (result.Outcome)
                    {
                        case SyncOutcome.PushedFresh:
                            Console.Error.WriteLine($"First push complete. Remote ETag: {result.ETag}");
                            break;
                        case SyncOutcome.PushedNoMerge:
                            Console.Error.WriteLine($"Pushed (remote was up to date). ETag: {result.ETag}");
                            break;
                        case SyncOutcome.Merged:
                            var m = result.MergeResult!;
                            Console.Error.WriteLine(
                                $"Merged: +{m.RemoteOnly} new, {m.LocalUpdated} updated, " +
                                $"{m.RemoteItemsDroppedByTombstone + m.LocalItemsDroppedByTombstone} deletions, " +
                                $"{m.Resurrections} resurrections.");
                            Console.Error.WriteLine($"Pushed merged. ETag: {result.ETag}");
                            break;
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                if (!quiet) Console.Error.WriteLine($"sync failed: {ex.Message}");
                else Console.WriteLine($"error {ex.GetType().Name}");
                return 3;
            }
        }
    }

    private static int CmdSyncStatus(string path)
    {
        var orch = new SyncOrchestrator(path);
        if (!orch.HasConfig)
        {
            Console.Error.WriteLine("Sync not configured.");
            return 1;
        }
        var state = orch.LoadState();
        Console.WriteLine($"Endpoint:        {state.Remote.Endpoint}");
        Console.WriteLine($"Bucket / key:    {state.Remote.Bucket} / {state.Remote.Key}");
        Console.WriteLine($"Last sync:       {state.LastSyncedAt?.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}");
        Console.WriteLine($"Last known ETag: {state.LastKnownETag}");
        return 0;
    }

    private static VaultSession OpenSession(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException($"no vault at {path}");
        var sk = Environment.GetEnvironmentVariable("VAULT_SECRET_KEY");
        if (string.IsNullOrEmpty(sk))
        {
            Console.Error.Write("Secret key: ");
            sk = Console.ReadLine() ?? "";
        }
        using var pwd = ConsolePassword.Read("Master password: ");
        return VaultSession.Unlock(path, pwd.AsReadOnlySpan(), sk);
    }
}
