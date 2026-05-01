using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Vault.Crypto;

/// <summary>
/// AES-256-GCM authenticated encryption.
///
/// Wire format: [12-byte nonce][ciphertext][16-byte tag]
///
/// Nonce policy: random 96-bit per encryption. Birthday bound is 2^32 messages
/// per key before collision risk becomes non-negligible. For a personal vault
/// this is fine; rotate keys on bulk re-encrypt anyway.
/// NEVER reuse a (key, nonce) pair — catastrophic for GCM.
/// </summary>
public static class AesGcmAead
{
    public const int KeySize = 32;       // AES-256
    public const int NonceSize = 12;     // 96-bit, GCM standard
    public const int TagSize = 16;       // 128-bit auth tag

    public static byte[] Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));

        var output = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        var ciphertext = output.AsSpan(NonceSize, plaintext.Length);
        var tag = output.AsSpan(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);

        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return output;
    }

    public static SecureBytes Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> envelope,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        if (envelope.Length < NonceSize + TagSize) throw new ArgumentException("Envelope too short");

        var nonce = envelope[..NonceSize];
        var ciphertext = envelope[NonceSize..^TagSize];
        var tag = envelope[^TagSize..];

        var plaintext = new SecureBytes(ciphertext.Length);
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext.AsSpan(), associatedData);
            return plaintext;
        }
        catch
        {
            plaintext.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Build a domain-separated AD blob: [version:u8][purpose:utf8][0x00][context...]
    /// Use this so the same key encrypting different things produces non-fungible ciphertexts.
    /// </summary>
    public static byte[] BuildAssociatedData(byte version, ReadOnlySpan<byte> purpose, ReadOnlySpan<byte> context = default)
    {
        var len = 1 + purpose.Length + 1 + context.Length;
        var ad = new byte[len];
        ad[0] = version;
        purpose.CopyTo(ad.AsSpan(1));
        ad[1 + purpose.Length] = 0x00;
        context.CopyTo(ad.AsSpan(2 + purpose.Length));
        return ad;
    }
}
