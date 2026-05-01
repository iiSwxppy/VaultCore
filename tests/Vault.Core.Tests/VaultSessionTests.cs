using Vault.Core;
using Vault.Core.Items;
using Vault.Crypto;
using Xunit;

namespace Vault.Core.Tests;

public class VaultSessionTests : IDisposable
{
    private readonly string _vaultPath;
    private readonly Argon2Kdf.Params _fastKdf = new(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 1);

    public VaultSessionTests()
    {
        _vaultPath = Path.Combine(Path.GetTempPath(), $"vault-test-{Guid.NewGuid():N}.vault");
    }

    public void Dispose()
    {
        if (File.Exists(_vaultPath)) File.Delete(_vaultPath);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Create_and_unlock_succeeds()
    {
        var pwd = "correct-horse-battery-staple"u8.ToArray();
        var sk = SecretKey.Generate();
        using (var s = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf)) { }

        using var session = VaultSession.Unlock(_vaultPath, pwd, sk);
        Assert.Empty(session.Items);
    }

    [Fact]
    public void Unlock_with_wrong_password_throws()
    {
        var pwd = "right-password"u8.ToArray();
        var wrongPwd = "wrong-password"u8.ToArray();
        var sk = SecretKey.Generate();

        using (var s = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf)) { }

        Assert.Throws<InvalidPasswordException>(() =>
            VaultSession.Unlock(_vaultPath, wrongPwd, sk));
    }

    [Fact]
    public void Unlock_with_wrong_secret_key_throws()
    {
        var pwd = "right-password"u8.ToArray();
        var sk1 = SecretKey.Generate();
        var sk2 = SecretKey.Generate();

        using (var s = VaultSession.Create(_vaultPath, pwd, sk1, _fastKdf)) { }

        Assert.Throws<InvalidPasswordException>(() =>
            VaultSession.Unlock(_vaultPath, pwd, sk2));
    }

    [Fact]
    public void Add_and_retrieve_login_item()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        Guid id;
        using (var session = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf))
        {
            id = session.AddItem(new LoginPayload
            {
                Title = "GitHub",
                Username = "calin",
                Password = "hunter2",
                Urls = ["https://github.com"],
            });
        }

        using var reopen = VaultSession.Unlock(_vaultPath, pwd, sk);
        Assert.Single(reopen.Items);
        var login = (LoginPayload)reopen.DecryptItem(id);
        Assert.Equal("GitHub", login.Title);
        Assert.Equal("calin", login.Username);
        Assert.Equal("hunter2", login.Password);
        Assert.Single(login.Urls);
    }

    [Fact]
    public void Update_changes_payload_and_keeps_id()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        using var session = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf);
        var id = session.AddItem(new LoginPayload { Title = "v1", Password = "old" });
        session.UpdateItem(id, new LoginPayload { Title = "v2", Password = "new" });

        var p = (LoginPayload)session.DecryptItem(id);
        Assert.Equal("v2", p.Title);
        Assert.Equal("new", p.Password);
    }

    [Fact]
    public void Delete_removes_item()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        using var session = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf);
        var id = session.AddItem(new SecureNotePayload { Title = "tmp", Body = "x" });
        Assert.True(session.DeleteItem(id));
        Assert.False(session.DeleteItem(id));
        Assert.Empty(session.Items);
    }

    [Fact]
    public void File_tampering_is_detected()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        using (var s = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf))
        {
            s.AddItem(new LoginPayload { Title = "victim", Password = "secret" });
        }

        // Flip a byte in the middle of the file (likely inside an item envelope).
        var bytes = File.ReadAllBytes(_vaultPath);
        bytes[bytes.Length / 2] ^= 0x01;
        File.WriteAllBytes(_vaultPath, bytes);

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
            VaultSession.Unlock(_vaultPath, pwd, sk));
    }

    [Fact]
    public void Multiple_items_round_trip()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        var ids = new List<Guid>();
        using (var session = VaultSession.Create(_vaultPath, pwd, sk, _fastKdf))
        {
            for (var i = 0; i < 25; i++)
            {
                ids.Add(session.AddItem(new LoginPayload
                {
                    Title = $"item-{i}",
                    Username = $"user{i}",
                    Password = $"pass-{i}-{Guid.NewGuid()}",
                }));
            }
        }

        using var reopen = VaultSession.Unlock(_vaultPath, pwd, sk);
        Assert.Equal(25, reopen.Items.Count);
        for (var i = 0; i < 25; i++)
        {
            var p = (LoginPayload)reopen.DecryptItem(ids[i]);
            Assert.Equal($"item-{i}", p.Title);
        }
    }
}
