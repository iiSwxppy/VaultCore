using System.Text.Json;
using Vault.Core;
using Vault.Crypto;

namespace Vault.Sync;

/// <summary>
/// Orchestrator for pull-merge-push sync flow.
///
/// Usage:
///   var orch = new SyncOrchestrator(localVaultPath, syncStatePath);
///   var result = await orch.SyncAsync(localSession, masterPassword, secretKey);
///
/// Where:
///   localVaultPath:  the .vault file (used only to read raw bytes for push)
///   syncStatePath:   sibling file storing the SyncState (remote config + ETag)
///
/// Flow:
///   1. HEAD remote → get current ETag
///   2. If remote has same ETag as our LastKnownETag → just push our local
///      (or no-op if nothing changed locally)
///   3. Otherwise pull, decrypt with same password+secretKey, merge into local
///      session, then push the merged file with If-Match=current_remote_etag
///   4. Record new ETag in sync state
///
/// On RemoteChangedException during push: retry up to 3 times. Hard fail
/// after that — the user can re-sync manually.
/// </summary>
public sealed class SyncOrchestrator
{
    private readonly string _localVaultPath;
    private readonly string _syncStatePath;

    public SyncOrchestrator(string localVaultPath, string? syncStatePath = null)
    {
        _localVaultPath = localVaultPath;
        _syncStatePath = syncStatePath ?? localVaultPath + ".sync";
    }

    public bool HasConfig => File.Exists(_syncStatePath);

    public SyncState LoadState()
    {
        if (!File.Exists(_syncStatePath))
            throw new InvalidOperationException("Sync not configured. Call ConfigureRemote first.");
        var json = File.ReadAllBytes(_syncStatePath);
        return JsonSerializer.Deserialize(json, SyncJsonContext.Default.SyncState)
            ?? throw new InvalidDataException("Bad sync state");
    }

    public void SaveState(SyncState state)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(state, SyncJsonContext.Default.SyncState);
        var tmp = _syncStatePath + ".tmp";
        File.WriteAllBytes(tmp, json);
        if (File.Exists(_syncStatePath)) File.Replace(tmp, _syncStatePath, null);
        else File.Move(tmp, _syncStatePath);

        // Best-effort tighten file mode (Linux/macOS).
        try
        {
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                File.SetUnixFileMode(_syncStatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch { /* ignore */ }
    }

    public void ConfigureRemote(SyncRemoteConfig config)
    {
        config.Validate();
        var existing = File.Exists(_syncStatePath) ? LoadState() : new SyncState();
        existing.Remote = config;
        SaveState(existing);
    }

    public async Task<SyncSummary> SyncAsync(
        VaultSession localSession,
        ReadOnlyMemory<byte> masterPassword,
        string secretKey,
        CancellationToken ct = default)
    {
        var state = LoadState();
        using var remote = new S3VaultRemote(state.Remote);

        const int maxRetries = 3;
        Exception? lastError = null;

        for (var attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                return await SyncOnceAsync(localSession, masterPassword, secretKey, state, remote, ct).ConfigureAwait(false);
            }
            catch (RemoteChangedException ex)
            {
                lastError = ex;
                // Race: someone pushed between our HEAD and PUT. Retry the whole flow.
                continue;
            }
        }
        throw new SyncException($"Sync failed after {maxRetries} attempts due to concurrent remote updates.", lastError);
    }

    private async Task<SyncSummary> SyncOnceAsync(
        VaultSession localSession,
        ReadOnlyMemory<byte> masterPassword,
        string secretKey,
        SyncState state,
        S3VaultRemote remote,
        CancellationToken ct)
    {
        // 1. HEAD remote
        string? remoteETag;
        try
        {
            remoteETag = await remote.HeadETagAsync(ct).ConfigureAwait(false);
        }
        catch (RemoteNotFoundException)
        {
            // Bucket exists but no object yet — first push.
            remoteETag = null;
        }

        if (remoteETag is null)
        {
            // First push ever. Just upload, record ETag.
            var pushedETag = await PushLocalAsync(remote, ifMatchETag: null, ct).ConfigureAwait(false);
            state.LastKnownETag = pushedETag;
            state.LastSyncedAt = DateTimeOffset.UtcNow;
            SaveState(state);
            return new SyncSummary(SyncOutcome.PushedFresh, MergeResult: null, ETag: pushedETag);
        }

        if (remoteETag == state.LastKnownETag)
        {
            // Remote unchanged since our last sync. Just push our local state.
            // (If local hadn't changed either, this is wasted work but cheap; we
            // could compare local file hash to detect no-op, future improvement.)
            var pushedETag = await PushLocalAsync(remote, ifMatchETag: remoteETag, ct).ConfigureAwait(false);
            state.LastKnownETag = pushedETag;
            state.LastSyncedAt = DateTimeOffset.UtcNow;
            SaveState(state);
            return new SyncSummary(SyncOutcome.PushedNoMerge, MergeResult: null, ETag: pushedETag);
        }

        // 2. Remote diverged. Pull, decrypt with the SAME credentials, merge.
        var (remoteBody, fetchedETag) = await remote.PullAsync(ct).ConfigureAwait(false);

        VaultManifest remoteManifest;
        IReadOnlyList<VaultFile.EncryptedItem> remoteItems;
        IReadOnlyList<VaultFile.EncryptedAuditEntry> remoteAudit;
        IReadOnlyList<Tombstone> remoteTombstones;
        SecureBytes remoteVaultKey;
        byte[] remoteFingerprint;
        try
        {
            (remoteManifest, remoteItems, remoteAudit, remoteTombstones, remoteVaultKey, remoteFingerprint) =
                VaultSession.DecryptBuffer(remoteBody, masterPassword.Span, secretKey);
        }
        catch (InvalidPasswordException)
        {
            throw new SyncException("Remote vault uses different credentials than the local vault.");
        }
        using (remoteVaultKey)
        {
            var localFingerprint = localSession.VaultKeyFingerprint();
            if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    localFingerprint, remoteFingerprint))
            {
                throw new SyncException(
                    "Remote vault has a different VaultKey. These are two distinct vaults — refusing to merge.");
            }

            var mergeResult = VaultMerger.MergeAndSave(localSession, remoteItems, remoteAudit, remoteTombstones);

            var pushedETag = await PushLocalAsync(remote, ifMatchETag: fetchedETag, ct).ConfigureAwait(false);
            state.LastKnownETag = pushedETag;
            state.LastSyncedAt = DateTimeOffset.UtcNow;
            SaveState(state);

            return new SyncSummary(SyncOutcome.Merged, mergeResult, pushedETag);
        }
    }

    private async Task<string> PushLocalAsync(S3VaultRemote remote, string? ifMatchETag, CancellationToken ct)
    {
        var bytes = await File.ReadAllBytesAsync(_localVaultPath, ct).ConfigureAwait(false);
        return await remote.PushAsync(bytes, ifMatchETag, ct).ConfigureAwait(false);
    }
}

public enum SyncOutcome
{
    /// <summary>Pushed the very first version (remote was empty).</summary>
    PushedFresh,
    /// <summary>Remote was unchanged since last sync; pushed local without merge.</summary>
    PushedNoMerge,
    /// <summary>Remote had diverged; pulled, merged locally, pushed merged version.</summary>
    Merged,
}

public sealed record SyncSummary(SyncOutcome Outcome, MergeResult? MergeResult, string ETag);
