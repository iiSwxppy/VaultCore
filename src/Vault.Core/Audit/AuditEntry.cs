namespace Vault.Core.Audit;

public enum AuditAction
{
    VaultCreated = 1,
    VaultUnlocked = 2,
    VaultUnlockFailed = 3,    // Reserved — we can only log this if we have keys, which we don't on failed unlock. Kept for future.
    ItemCreated = 10,
    ItemUpdated = 11,
    ItemDeleted = 12,
    ItemDecrypted = 13,
    MasterPasswordChanged = 20,
    EncryptedBackupExported = 30,
    PlaintextExported = 31,    // High-severity event, always logged
    ImportPerformed = 40,
    MaintenancePerformed = 50, // Tombstone pruning, audit log truncation, etc.
}

public sealed record AuditEntry(
    DateTimeOffset Timestamp,
    AuditAction Action,
    Guid? ItemId,
    string? Details);
