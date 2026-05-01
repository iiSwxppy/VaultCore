using Konscious.Security.Cryptography;

namespace Vault.Crypto;

/// <summary>
/// Argon2id key derivation. Parameters per RFC 9106 recommendations,
/// tuned for ~500ms-1s on a modern desktop CPU. Measure on your hardware.
/// </summary>
public static class Argon2Kdf
{
    public sealed record Params(int MemoryKib, int Iterations, int Parallelism)
    {
        /// <summary>Reasonable interactive defaults (~64 MiB, 3 passes, 4 lanes).</summary>
        public static Params Default => new(MemoryKib: 64 * 1024, Iterations: 3, Parallelism: 4);

        /// <summary>For sensitive vaults, tune up. Measure unlock time before shipping.</summary>
        public static Params Sensitive => new(MemoryKib: 256 * 1024, Iterations: 4, Parallelism: 4);

        public void Validate()
        {
            if (MemoryKib < 8 * 1024) throw new ArgumentException("MemoryKib must be >= 8 MiB");
            if (Iterations < 1) throw new ArgumentException("Iterations must be >= 1");
            if (Parallelism is < 1 or > 64) throw new ArgumentException("Parallelism must be 1..64");
        }
    }

    /// <summary>
    /// Derive <paramref name="outputLength"/> bytes from password + salt.
    /// Salt MUST be at least 16 bytes and unique per vault.
    /// </summary>
    public static SecureBytes Derive(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Params parameters,
        int outputLength,
        ReadOnlySpan<byte> associatedData = default,
        ReadOnlySpan<byte> knownSecret = default)
    {
        parameters.Validate();
        if (salt.Length < 16) throw new ArgumentException("Salt must be >= 16 bytes", nameof(salt));
        if (outputLength is < 4 or > 1024) throw new ArgumentOutOfRangeException(nameof(outputLength));

        // Konscious takes byte[]; copy password locally so we can zero it after.
        var pwdCopy = password.ToArray();
        try
        {
            using var argon = new Argon2id(pwdCopy)
            {
                Salt = salt.ToArray(),
                DegreeOfParallelism = parameters.Parallelism,
                MemorySize = parameters.MemoryKib,
                Iterations = parameters.Iterations,
            };
            if (!associatedData.IsEmpty) argon.AssociatedData = associatedData.ToArray();
            if (!knownSecret.IsEmpty) argon.KnownSecret = knownSecret.ToArray();

            var raw = argon.GetBytes(outputLength);
            try
            {
                return new SecureBytes(raw);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(raw);
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(pwdCopy);
        }
    }
}
