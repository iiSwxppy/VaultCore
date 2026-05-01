using Vault.Core;

namespace Vault.Sync;

public sealed record MergeResult(
    int LocalAdded,
    int LocalUpdated,
    int RemoteOnly,
    int LocalOnly,
    int Conflicts,
    int AuditEntriesCombined,
    int TombstonesAdded,
    int RemoteItemsDroppedByTombstone,
    int LocalItemsDroppedByTombstone,
    int Resurrections);

/// <summary>
/// Three-way merge between local and remote vault contents, with tombstone-driven
/// delete propagation.
///
/// Algorithm:
///   1. Union tombstones from both sides. If both sides have a tombstone for
///      the same id, keep the LATER DeletedAt.
///   2. Build the merged item set:
///      - For each unique id in (local ∪ remote):
///          a. If a tombstone exists for this id with DeletedAt &gt;= max(UpdatedAt
///             of either side), the item stays deleted on both sides. Drop.
///          b. Else if both sides have it, the side with newer UpdatedAt wins.
///          c. Else (one side only) keep it.
///      - "Resurrection": if an item's UpdatedAt &gt; the tombstone's DeletedAt,
///        the user re-created it after deletion. Drop the tombstone, keep the item.
///   3. Audit: union of encrypted entries, sorted by timestamp.
/// </summary>
public static class VaultMerger
{
    public static MergeResult MergeAndSave(
        VaultSession localSession,
        IReadOnlyList<VaultFile.EncryptedItem> remoteItems,
        IReadOnlyList<VaultFile.EncryptedAuditEntry> remoteAudit,
        IReadOnlyList<Tombstone> remoteTombstones)
    {
        var localItems = localSession.Items.ToDictionary(i => i.Id);
        var remoteItemsDict = remoteItems.ToDictionary(i => i.Id);
        var localTombstones = localSession.Tombstones.ToDictionary(t => t.ItemId);
        var remoteTombstonesDict = remoteTombstones.ToDictionary(t => t.ItemId);

        // Step 1: union tombstones, keep later DeletedAt.
        var mergedTombstones = new Dictionary<Guid, Tombstone>(localTombstones);
        var tombstonesAdded = 0;
        foreach (var (id, remoteTomb) in remoteTombstonesDict)
        {
            if (mergedTombstones.TryGetValue(id, out var existing))
            {
                if (remoteTomb.DeletedAt > existing.DeletedAt)
                    mergedTombstones[id] = remoteTomb;
            }
            else
            {
                mergedTombstones[id] = remoteTomb;
                tombstonesAdded++;
            }
        }

        var allIds = new HashSet<Guid>(localItems.Keys);
        foreach (var id in remoteItemsDict.Keys) allIds.Add(id);

        var merged = new Dictionary<Guid, VaultFile.EncryptedItem>();
        var localOnly = 0;
        var remoteOnly = 0;
        var localUpdated = 0;
        var conflicts = 0;
        var remoteDroppedByTombstone = 0;
        var localDroppedByTombstone = 0;
        var resurrections = 0;

        foreach (var id in allIds)
        {
            localItems.TryGetValue(id, out var local);
            remoteItemsDict.TryGetValue(id, out var remote);
            mergedTombstones.TryGetValue(id, out var tomb);

            // Determine "effective" item: newer of local / remote, or null if neither.
            VaultFile.EncryptedItem? effective = null;
            if (local is not null && remote is not null)
            {
                effective = remote.UpdatedAt > local.UpdatedAt ? remote : local;
                if (remote.UpdatedAt > local.UpdatedAt) localUpdated++;
                if (local.UpdatedAt != remote.UpdatedAt) conflicts++;
            }
            else if (local is not null)
            {
                effective = local;
                localOnly++;
            }
            else if (remote is not null)
            {
                effective = remote;
                remoteOnly++;
            }

            // Apply tombstone rule.
            if (tomb is not null && effective is not null)
            {
                if (effective.UpdatedAt > tomb.DeletedAt)
                {
                    // Resurrection: user re-created after delete. Drop tombstone, keep item.
                    mergedTombstones.Remove(id);
                    resurrections++;
                    merged[id] = effective;
                }
                else
                {
                    // Tombstone wins. Drop the item from both sides.
                    if (remote is not null && (local is null || effective == remote))
                        remoteDroppedByTombstone++;
                    if (local is not null)
                        localDroppedByTombstone++;
                    // Don't add to merged.
                }
            }
            else if (effective is not null)
            {
                merged[id] = effective;
            }
        }

        // Audit log union, sorted.
        var combinedAudit = localSession.AuditEntriesEncrypted
            .Concat(remoteAudit)
            .OrderBy(e => e.Timestamp)
            .ToList();

        localSession.ReplaceItemsAuditAndTombstones(merged.Values, combinedAudit, mergedTombstones.Values);

        return new MergeResult(
            LocalAdded: 0,
            LocalUpdated: localUpdated,
            RemoteOnly: remoteOnly,
            LocalOnly: localOnly,
            Conflicts: conflicts,
            AuditEntriesCombined: combinedAudit.Count,
            TombstonesAdded: tombstonesAdded,
            RemoteItemsDroppedByTombstone: remoteDroppedByTombstone,
            LocalItemsDroppedByTombstone: localDroppedByTombstone,
            Resurrections: resurrections);
    }
}
