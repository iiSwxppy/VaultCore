using Xunit;

namespace Vault.Crypto.Tests;

public class AesGcmAeadTests
{
    [Fact]
    public void RoundTrip_recovers_plaintext()
    {
        var key = RandomBytes.Get(32);
        var plaintext = "hello, secret world"u8.ToArray();
        var ad = "context"u8.ToArray();

        var envelope = AesGcmAead.Encrypt(key, plaintext, ad);
        using var recovered = AesGcmAead.Decrypt(key, envelope, ad);

        Assert.Equal(plaintext, recovered.AsReadOnlySpan().ToArray());
    }

    [Fact]
    public void Decrypt_with_wrong_key_throws()
    {
        var key1 = RandomBytes.Get(32);
        var key2 = RandomBytes.Get(32);
        var envelope = AesGcmAead.Encrypt(key1, "data"u8);
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
            AesGcmAead.Decrypt(key2, envelope));
    }

    [Fact]
    public void Decrypt_with_tampered_ciphertext_throws()
    {
        var key = RandomBytes.Get(32);
        var envelope = AesGcmAead.Encrypt(key, "data"u8);
        envelope[envelope.Length / 2] ^= 0x01;
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
            AesGcmAead.Decrypt(key, envelope));
    }

    [Fact]
    public void Decrypt_with_wrong_associated_data_throws()
    {
        var key = RandomBytes.Get(32);
        var envelope = AesGcmAead.Encrypt(key, "data"u8, "ad-A"u8);
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
            AesGcmAead.Decrypt(key, envelope, "ad-B"u8));
    }

    [Fact]
    public void Two_encryptions_produce_different_envelopes()
    {
        var key = RandomBytes.Get(32);
        var e1 = AesGcmAead.Encrypt(key, "data"u8);
        var e2 = AesGcmAead.Encrypt(key, "data"u8);
        Assert.NotEqual(e1, e2); // different nonces
    }

    [Fact]
    public void Wrong_key_size_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            AesGcmAead.Encrypt(new byte[16], "data"u8));
    }
}
