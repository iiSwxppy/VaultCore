using System.Security.Cryptography;
using System.Text;

namespace Vault.Crypto;

/// <summary>
/// Cryptographic randomness helpers and Secret Key encoding.
///
/// Secret Key format (1Password-inspired):
///   A1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
///   - "A1" = format version
///   - 6 groups of 6 chars from base32-like alphabet (no 0/O/1/I/L)
///   - 36 chars * ~5.17 bits/char ≈ 186 bits of entropy
/// </summary>
public static class SecretKey
{
    private const string Alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"; // 31 chars, removed confusables
    private const int GroupCount = 6;
    private const int GroupSize = 6;
    private const string Version = "A1";

    public static string Generate()
    {
        Span<char> buf = stackalloc char[Version.Length + 1 + GroupCount * (GroupSize + 1) - 1];
        var pos = 0;
        Version.AsSpan().CopyTo(buf[pos..]); pos += Version.Length;

        for (var g = 0; g < GroupCount; g++)
        {
            buf[pos++] = '-';
            for (var i = 0; i < GroupSize; i++)
            {
                buf[pos++] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
            }
        }

        return new string(buf);
    }

    public static bool TryParse(string input, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(input)) return false;

        var clean = new StringBuilder(40);
        foreach (var c in input.ToUpperInvariant())
        {
            if (c is '-' or ' ') continue;
            clean.Append(c);
        }

        if (clean.Length != Version.Length + GroupCount * GroupSize) return false;
        if (clean.ToString(0, Version.Length) != Version) return false;
        for (var i = Version.Length; i < clean.Length; i++)
        {
            if (Alphabet.IndexOf(clean[i]) < 0) return false;
        }

        var formatted = new StringBuilder();
        formatted.Append(clean, 0, Version.Length);
        for (var g = 0; g < GroupCount; g++)
        {
            formatted.Append('-');
            formatted.Append(clean, Version.Length + g * GroupSize, GroupSize);
        }
        normalized = formatted.ToString();
        return true;
    }

    /// <summary>
    /// Hash the Secret Key string into 32 raw bytes for use as HKDF salt.
    /// SHA-256 is fine here — the key already has high entropy.
    /// </summary>
    public static byte[] ToBytes(string normalizedSecretKey)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(normalizedSecretKey));
    }
}

public static class RandomBytes
{
    public static byte[] Get(int length)
    {
        var b = new byte[length];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    public static byte[] Salt() => Get(16);
    public static byte[] AccountId() => Get(16);
}
