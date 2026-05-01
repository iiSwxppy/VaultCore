using System.Security.Cryptography;

namespace Vault.Crypto;

/// <summary>
/// HKDF-SHA256 (RFC 5869). Used to derive sub-keys from a master key
/// (e.g. AUK from MUK + Secret Key, or per-purpose keys from vault key).
/// </summary>
public static class Hkdf
{
    public static SecureBytes DeriveKey(
        ReadOnlySpan<byte> ikm,
        int outputLength,
        ReadOnlySpan<byte> salt = default,
        ReadOnlySpan<byte> info = default)
    {
        if (outputLength is < 1 or > 8160) throw new ArgumentOutOfRangeException(nameof(outputLength));

        var output = new SecureBytes(outputLength);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output.AsSpan(), salt, info);
        return output;
    }

    public static SecureBytes Combine2SKD(
        ReadOnlySpan<byte> muk,
        ReadOnlySpan<byte> secretKey,
        ReadOnlySpan<byte> accountId,
        int outputLength = 32)
    {
        // Two-Secret Key Derivation:
        // AUK = HKDF(salt = secretKey, ikm = muk, info = "vault-auk-v1" || accountId)
        Span<byte> info = stackalloc byte[12 + accountId.Length];
        "vault-auk-v1"u8.CopyTo(info);
        accountId.CopyTo(info[12..]);
        return DeriveKey(muk, outputLength, salt: secretKey, info: info);
    }
}
