namespace Vault.Core;

/// <summary>
/// Tombstone for a deleted item. Stored encrypted under VaultKey alongside
/// items, in its own section of the vault file (format v3+).
///
/// Purpose: propagate deletes across synced devices. Without tombstones,
/// device A deleting an item just removes it locally; on next sync from
/// device B, B's still-present item gets merged BACK INTO A. With tombstones,
/// the merge sees `tombstone(id, deletedAt)` on A and drops the corresponding
/// remote item if its UpdatedAt < deletedAt.
///
/// Resurrection rule: if remote has the item with UpdatedAt > deletedAt, the
/// user explicitly re-created it after the delete (rare but valid). The
/// tombstone is dropped, the remote item is kept.
///
/// Garbage collection: tombstones older than ~90 days can be pruned, but
/// pruning is unsafe if any device hasn't synced since the deletion (it
/// would resurrect on next sync from that device). For personal multi-device
/// use we keep tombstones indefinitely — they're tiny.
/// </summary>
public sealed record Tombstone(Guid ItemId, DateTimeOffset DeletedAt);
