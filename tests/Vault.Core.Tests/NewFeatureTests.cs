using System.Text;
using Vault.Core.Export;
using Vault.Core.Import;
using Vault.Core.Items;
using Vault.Crypto;
using Xunit;

namespace Vault.Core.Tests;

public class ChangeMasterPasswordTests : IDisposable
{
    private readonly string _vaultPath = Path.Combine(Path.GetTempPath(), $"vault-cmp-{Guid.NewGuid():N}.vault");
    private readonly Argon2Kdf.Params _fastKdf = new(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 1);

    public void Dispose()
    {
        if (File.Exists(_vaultPath)) File.Delete(_vaultPath);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Old_password_no_longer_works_after_rotation()
    {
        var oldPwd = "old-password"u8.ToArray();
        var newPwd = "new-password-much-longer"u8.ToArray();
        var sk = SecretKey.Generate();

        Guid id;
        using (var s = VaultSession.Create(_vaultPath, oldPwd, sk, _fastKdf))
        {
            id = s.AddItem(new LoginPayload { Title = "test", Password = "secret" });
            s.ChangeMasterPassword(newPwd, sk, _fastKdf);
        }

        Assert.Throws<InvalidPasswordException>(() =>
            VaultSession.Unlock(_vaultPath, oldPwd, sk));

        using var reopen = VaultSession.Unlock(_vaultPath, newPwd, sk);
        var p = (LoginPayload)reopen.DecryptItem(id);
        Assert.Equal("secret", p.Password);
    }

    [Fact]
    public void Items_are_unchanged_after_rotation()
    {
        var oldPwd = "old"u8.ToArray();
        var newPwd = "new"u8.ToArray();
        var sk = SecretKey.Generate();

        byte[] beforeEnvelope;
        Guid id;
        using (var s = VaultSession.Create(_vaultPath, oldPwd, sk, _fastKdf))
        {
            id = s.AddItem(new LoginPayload { Title = "x", Password = "y" });
            beforeEnvelope = s.Items.Single().Envelope;
            s.ChangeMasterPassword(newPwd, sk, _fastKdf);
        }

        // After rotation, item envelope must be byte-identical (only manifest changed).
        using var reopen = VaultSession.Unlock(_vaultPath, newPwd, sk);
        Assert.Equal(beforeEnvelope, reopen.Items.Single().Envelope);
    }
}

public class HibpCheckerTests
{
    [Fact]
    public async Task Known_pwned_password_is_detected()
    {
        // 'password' has been pwned billions of times. Stable test.
        // Skip if no network / CI offline.
        if (Environment.GetEnvironmentVariable("VAULT_SKIP_NETWORK_TESTS") == "1") return;

        var hibp = new HibpChecker();
        try
        {
            var count = await hibp.CheckPasswordAsync("password");
            Assert.True(count > 1_000_000, $"expected > 1M, got {count}");
        }
        catch (HttpRequestException)
        {
            // Network not available in this environment — not a logic failure.
        }
    }

    [Fact]
    public async Task Random_strong_password_not_in_hibp()
    {
        if (Environment.GetEnvironmentVariable("VAULT_SKIP_NETWORK_TESTS") == "1") return;

        var hibp = new HibpChecker();
        var unique = "vault-test-" + Guid.NewGuid() + "-" + Guid.NewGuid();
        try
        {
            var count = await hibp.CheckPasswordAsync(unique);
            Assert.Equal(0, count);
        }
        catch (HttpRequestException)
        {
            // Treat as inconclusive.
        }
    }
}

public class BitwardenImporterTests : IDisposable
{
    private readonly string _vaultPath = Path.Combine(Path.GetTempPath(), $"vault-bw-{Guid.NewGuid():N}.vault");
    private readonly Argon2Kdf.Params _fastKdf = new(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 1);

    public void Dispose()
    {
        if (File.Exists(_vaultPath)) File.Delete(_vaultPath);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Imports_login_card_and_note()
    {
        var json = """
        {
          "encrypted": false,
          "folders": [{ "id": "f1", "name": "Personal" }],
          "items": [
            {
              "type": 1,
              "name": "GitHub",
              "folderId": "f1",
              "login": {
                "username": "calin",
                "password": "hunter2",
                "uris": [{ "uri": "https://github.com" }],
                "totp": "JBSWY3DPEHPK3PXP"
              }
            },
            {
              "type": 2,
              "name": "Recovery codes",
              "notes": "abc-123\ndef-456"
            },
            {
              "type": 3,
              "name": "Visa",
              "card": {
                "cardholderName": "CALIN ION",
                "number": "4111111111111111",
                "expMonth": "12",
                "expYear": "2030",
                "code": "123",
                "brand": "Visa"
              }
            }
          ]
        }
        """;

        using var session = VaultSession.Create(_vaultPath, "p"u8, SecretKey.Generate(), _fastKdf);
        var report = BitwardenImporter.Import(Encoding.UTF8.GetBytes(json), session);

        Assert.Equal(3, report.TotalRead);
        Assert.Equal(3, report.Imported);
        Assert.Equal(0, report.Skipped);

        var items = session.Items.ToList();
        Assert.Equal(3, items.Count);

        var login = items.Single(i => i.Type == ItemType.Login);
        var p = (LoginPayload)session.DecryptItem(login.Id);
        Assert.Equal("GitHub", p.Title);
        Assert.Equal("calin", p.Username);
        Assert.Equal("hunter2", p.Password);
        Assert.Single(p.Urls);
        Assert.Equal("JBSWY3DPEHPK3PXP", p.TotpSecret);
        Assert.Contains("Personal", p.Tags);
    }

    [Fact]
    public void Refuses_encrypted_export()
    {
        var json = """{"encrypted": true, "items": []}""";
        using var session = VaultSession.Create(_vaultPath, "p"u8, SecretKey.Generate(), _fastKdf);
        Assert.Throws<NotSupportedException>(() =>
            BitwardenImporter.Import(Encoding.UTF8.GetBytes(json), session));
    }
}

public class ExportTests : IDisposable
{
    private readonly string _vaultPath = Path.Combine(Path.GetTempPath(), $"vault-exp-{Guid.NewGuid():N}.vault");
    private readonly string _outputPath = Path.Combine(Path.GetTempPath(), $"vault-exp-out-{Guid.NewGuid():N}.json");
    private readonly Argon2Kdf.Params _fastKdf = new(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 1);

    public void Dispose()
    {
        if (File.Exists(_vaultPath)) File.Delete(_vaultPath);
        if (File.Exists(_outputPath)) File.Delete(_outputPath);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Encrypted_backup_is_unlockable()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();
        using (var s = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf))
        {
            s.AddItem(new LoginPayload { Title = "x", Password = "y" });
        }

        var backup = _vaultPath + ".bak";
        try
        {
            VaultExporter.ExportEncryptedBackup(_vaultPath, backup);
            using var reopen = VaultSession.Unlock(backup, pwd, sk);
            Assert.Single(reopen.Items);
        }
        finally
        {
            if (File.Exists(backup)) File.Delete(backup);
        }
    }

    [Fact]
    public void Plaintext_export_contains_secrets()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();
        using (var s = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf))
        {
            s.AddItem(new LoginPayload { Title = "github", Password = "BANANA-RAMA-1234" });
            VaultExporter.ExportPlaintextJson(s, _outputPath);
        }

        var content = File.ReadAllText(_outputPath);
        Assert.Contains("github", content, StringComparison.Ordinal);
        Assert.Contains("BANANA-RAMA-1234", content, StringComparison.Ordinal);
    }
}
