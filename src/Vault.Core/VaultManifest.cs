namespace Vault.Core;

/// <summary>
/// Plaintext manifest describing the vault file. Stored in the `vault_meta` table.
/// Contains everything needed to derive AUK from password + Secret Key.
/// Does NOT contain any secret material.
/// </summary>
public sealed record VaultManifest
{
    public int FormatVersion { get; init; } = 1;
    public required string AccountId { get; init; }       // hex, 16 bytes random per vault
    public required string KdfSaltHex { get; init; }      // hex, 16+ bytes
    public required int Argon2MemoryKib { get; init; }
    public required int Argon2Iterations { get; init; }
    public required int Argon2Parallelism { get; init; }

    /// <summary>
    /// AES-GCM envelope over a fixed plaintext ("vault-verify-v1") encrypted with AUK.
    /// On unlock we decrypt this; success proves password+SecretKey are correct
    /// without decrypting any user data.
    /// </summary>
    public required string AukVerifierEnvelopeHex { get; init; }

    /// <summary>
    /// AES-GCM envelope containing the 32-byte VaultKey, encrypted under AUK.
    /// VaultKey is what we actually use to derive per-item keys (so we can
    /// rotate AUK without re-encrypting every item).
    /// </summary>
    public required string VaultKeyEnvelopeHex { get; init; }

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;
}
