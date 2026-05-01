using Xunit;

namespace Vault.Crypto.Tests;

public class Argon2KdfTests
{
    [Fact]
    public void Same_inputs_produce_same_output()
    {
        var pwd = "test-password"u8.ToArray();
        var salt = new byte[16];
        for (var i = 0; i < salt.Length; i++) salt[i] = (byte)i;

        // Use small params to keep test fast.
        var p = new Argon2Kdf.Params(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 1);
        using var k1 = Argon2Kdf.Derive(pwd, salt, p, 32);
        using var k2 = Argon2Kdf.Derive(pwd, salt, p, 32);
        Assert.Equal(k1.AsReadOnlySpan().ToArray(), k2.AsReadOnlySpan().ToArray());
    }

    [Fact]
    public void Different_salt_produces_different_output()
    {
        var pwd = "test-password"u8.ToArray();
        var salt1 = new byte[16];
        var salt2 = new byte[16]; salt2[0] = 1;

        var p = new Argon2Kdf.Params(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 1);
        using var k1 = Argon2Kdf.Derive(pwd, salt1, p, 32);
        using var k2 = Argon2Kdf.Derive(pwd, salt2, p, 32);
        Assert.NotEqual(k1.AsReadOnlySpan().ToArray(), k2.AsReadOnlySpan().ToArray());
    }

    [Fact]
    public void Rejects_short_salt()
    {
        var p = Argon2Kdf.Params.Default;
        Assert.Throws<ArgumentException>(() =>
            Argon2Kdf.Derive("pwd"u8, new byte[8], p, 32));
    }

    [Fact]
    public void Rejects_invalid_params()
    {
        Assert.Throws<ArgumentException>(() =>
            new Argon2Kdf.Params(MemoryKib: 1024, Iterations: 1, Parallelism: 1).Validate());
        Assert.Throws<ArgumentException>(() =>
            new Argon2Kdf.Params(MemoryKib: 8 * 1024, Iterations: 0, Parallelism: 1).Validate());
        Assert.Throws<ArgumentException>(() =>
            new Argon2Kdf.Params(MemoryKib: 8 * 1024, Iterations: 1, Parallelism: 0).Validate());
    }
}

public class HkdfTests
{
    [Fact]
    public void Same_inputs_produce_same_output()
    {
        var ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        using var k1 = Hkdf.DeriveKey(ikm, 32, salt: "salt"u8, info: "info"u8);
        using var k2 = Hkdf.DeriveKey(ikm, 32, salt: "salt"u8, info: "info"u8);
        Assert.Equal(k1.AsReadOnlySpan().ToArray(), k2.AsReadOnlySpan().ToArray());
    }

    [Fact]
    public void Different_info_produces_different_output()
    {
        var ikm = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        using var k1 = Hkdf.DeriveKey(ikm, 32, info: "purpose-A"u8);
        using var k2 = Hkdf.DeriveKey(ikm, 32, info: "purpose-B"u8);
        Assert.NotEqual(k1.AsReadOnlySpan().ToArray(), k2.AsReadOnlySpan().ToArray());
    }
}
