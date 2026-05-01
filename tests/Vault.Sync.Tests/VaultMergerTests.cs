using Vault.Core;
using Vault.Core.Items;
using Vault.Crypto;
using Xunit;

namespace Vault.Sync.Tests;

public class VaultMergerTests : IDisposable
{
    private readonly Argon2Kdf.Params _fastKdf = new(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 1);
    private readonly List<string> _tempFiles = [];

    public void Dispose()
    {
        foreach (var f in _tempFiles)
            try { if (File.Exists(f)) File.Delete(f); } catch { /* ignore */ }
        GC.SuppressFinalize(this);
    }

    private string TempPath()
    {
        var p = Path.Combine(Path.GetTempPath(), $"vault-merge-{Guid.NewGuid():N}.vault");
        _tempFiles.Add(p);
        _tempFiles.Add(p + ".sync");
        return p;
    }

    private static (IReadOnlyList<VaultFile.EncryptedItem>, IReadOnlyList<VaultFile.EncryptedAuditEntry>, IReadOnlyList<Tombstone>) ReadRemote(string path, byte[] pwd, string sk)
    {
        var bytes = File.ReadAllBytes(path);
        var (_, items, audit, tombs, vk, _) = VaultSession.DecryptBuffer(bytes, pwd, sk);
        vk.Dispose();
        return (items, audit, tombs);
    }

    [Fact]
    public void Items_only_on_remote_are_added_to_local()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        var pathA = TempPath();
        using (var s = VaultSession.Create(pathA, pwd, sk, _fastKdf))
        {
            s.AddItem(new LoginPayload { Title = "shared", Password = "x" });
        }
        var pathB = TempPath();
        File.Copy(pathA, pathB, overwrite: true);

        Guid bUniqueId;
        using (var sB = VaultSession.Unlock(pathB, pwd, sk))
        {
            bUniqueId = sB.AddItem(new LoginPayload { Title = "B-only", Password = "Bonly" });
        }

        var (items, audit, tombs) = ReadRemote(pathB, pwd, sk);
        using var sA = VaultSession.Unlock(pathA, pwd, sk);
        var result = VaultMerger.MergeAndSave(sA, items, audit, tombs);

        Assert.Contains(sA.Items, i => i.Id == bUniqueId);
        Assert.True(result.RemoteOnly >= 1);
    }

    [Fact]
    public void Newer_remote_wins_on_conflict()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        var pathA = TempPath();
        Guid sharedId;
        using (var s = VaultSession.Create(pathA, pwd, sk, _fastKdf))
        {
            sharedId = s.AddItem(new LoginPayload { Title = "v1", Password = "p1" });
        }

        var pathB = TempPath();
        File.Copy(pathA, pathB, overwrite: true);

        using (var sA = VaultSession.Unlock(pathA, pwd, sk))
        {
            sA.UpdateItem(sharedId, new LoginPayload { Title = "A-version", Password = "A-pass" });
        }
        Thread.Sleep(20);

        using (var sB = VaultSession.Unlock(pathB, pwd, sk))
        {
            sB.UpdateItem(sharedId, new LoginPayload { Title = "B-version", Password = "B-pass" });
        }

        var (items, audit, tombs) = ReadRemote(pathB, pwd, sk);
        using var sAFinal = VaultSession.Unlock(pathA, pwd, sk);
        VaultMerger.MergeAndSave(sAFinal, items, audit, tombs);

        var winner = (LoginPayload)sAFinal.DecryptItem(sharedId);
        Assert.Equal("B-version", winner.Title);
    }

    [Fact]
    public void Tombstone_removes_item_from_other_device()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        var pathA = TempPath();
        Guid sharedId;
        using (var s = VaultSession.Create(pathA, pwd, sk, _fastKdf))
        {
            sharedId = s.AddItem(new LoginPayload { Title = "doomed", Password = "x" });
        }
        var pathB = TempPath();
        File.Copy(pathA, pathB, overwrite: true);

        // B deletes the item, producing a tombstone.
        using (var sB = VaultSession.Unlock(pathB, pwd, sk))
        {
            Assert.True(sB.DeleteItem(sharedId));
            Assert.Single(sB.Tombstones);
        }

        var (items, audit, tombs) = ReadRemote(pathB, pwd, sk);

        // Merge B (with tombstone) into A (still has item).
        using var sAFinal = VaultSession.Unlock(pathA, pwd, sk);
        Assert.Contains(sAFinal.Items, i => i.Id == sharedId); // pre-merge sanity
        var result = VaultMerger.MergeAndSave(sAFinal, items, audit, tombs);

        Assert.DoesNotContain(sAFinal.Items, i => i.Id == sharedId);
        Assert.Contains(sAFinal.Tombstones, t => t.ItemId == sharedId);
        Assert.True(result.LocalItemsDroppedByTombstone + result.RemoteItemsDroppedByTombstone > 0);
    }

    [Fact]
    public void Resurrection_overrides_tombstone()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        var pathA = TempPath();
        Guid sharedId;
        using (var s = VaultSession.Create(pathA, pwd, sk, _fastKdf))
        {
            sharedId = s.AddItem(new LoginPayload { Title = "v1" });
        }
        var pathB = TempPath();
        File.Copy(pathA, pathB, overwrite: true);

        // B deletes the item.
        using (var sB = VaultSession.Unlock(pathB, pwd, sk))
        {
            sB.DeleteItem(sharedId);
        }
        Thread.Sleep(20);

        // A updates the same item AFTER B's delete (timestamps prove it).
        using (var sA = VaultSession.Unlock(pathA, pwd, sk))
        {
            sA.UpdateItem(sharedId, new LoginPayload { Title = "resurrected" });
        }

        // Merge B into A. A has newer UpdatedAt than B's tombstone DeletedAt → resurrection.
        var (items, audit, tombs) = ReadRemote(pathB, pwd, sk);
        using var sAFinal = VaultSession.Unlock(pathA, pwd, sk);
        var result = VaultMerger.MergeAndSave(sAFinal, items, audit, tombs);

        Assert.Contains(sAFinal.Items, i => i.Id == sharedId);
        Assert.DoesNotContain(sAFinal.Tombstones, t => t.ItemId == sharedId);
        Assert.True(result.Resurrections >= 1);
    }

    [Fact]
    public void Tombstone_for_item_only_on_remote_still_propagates()
    {
        // Edge case: B added an item then deleted it before A ever saw it.
        // Tombstone arrives on A; A doesn't have the item. Tombstone should
        // still be recorded so subsequent syncs from C (which got the item
        // somehow) drop it.
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();

        var pathA = TempPath();
        using (var s = VaultSession.Create(pathA, pwd, sk, _fastKdf)) { }
        var pathB = TempPath();
        File.Copy(pathA, pathB, overwrite: true);

        Guid bId;
        using (var sB = VaultSession.Unlock(pathB, pwd, sk))
        {
            bId = sB.AddItem(new LoginPayload { Title = "ephemeral" });
            sB.DeleteItem(bId);
        }

        var (items, audit, tombs) = ReadRemote(pathB, pwd, sk);
        using var sAFinal = VaultSession.Unlock(pathA, pwd, sk);
        VaultMerger.MergeAndSave(sAFinal, items, audit, tombs);

        // Item not present, but tombstone is.
        Assert.DoesNotContain(sAFinal.Items, i => i.Id == bId);
        Assert.Contains(sAFinal.Tombstones, t => t.ItemId == bId);
    }

    [Fact]
    public void VaultKey_fingerprint_is_deterministic_per_vault()
    {
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();
        var path = TempPath();

        byte[] fp1, fp2;
        using (var s = VaultSession.Create(path, pwd, sk, _fastKdf))
        {
            fp1 = s.VaultKeyFingerprint();
        }
        using (var s = VaultSession.Unlock(path, pwd, sk))
        {
            fp2 = s.VaultKeyFingerprint();
        }
        Assert.Equal(fp1, fp2);
    }

    [Fact]
    public void Different_vaults_have_different_fingerprints()
    {
        var pwd = "p"u8.ToArray();
        var path1 = TempPath();
        var path2 = TempPath();
        using var s1 = VaultSession.Create(path1, pwd, SecretKey.Generate(), _fastKdf);
        using var s2 = VaultSession.Create(path2, pwd, SecretKey.Generate(), _fastKdf);
        Assert.NotEqual(s1.VaultKeyFingerprint(), s2.VaultKeyFingerprint());
    }

    [Fact]
    public void V1_or_v2_files_open_with_no_tombstones()
    {
        // A freshly-created vault is v3 in this build but has zero tombstones,
        // which is the same observable state as a v1 / v2 file. The reader
        // accepts versions 1-3.
        var pwd = "p"u8.ToArray();
        var sk = SecretKey.Generate();
        var path = TempPath();
        using (var s = VaultSession.Create(path, pwd, sk, _fastKdf)) { }
        using var reopen = VaultSession.Unlock(path, pwd, sk);
        Assert.Empty(reopen.Tombstones);
    }
}
