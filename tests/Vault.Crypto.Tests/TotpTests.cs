using Xunit;

namespace Vault.Crypto.Tests;

/// <summary>
/// Test vectors from RFC 6238 Appendix B. Use the documented secret
/// "12345678901234567890" (ASCII) for SHA1, longer for SHA256/512.
/// </summary>
public class TotpTests
{
    private const string Sha1Secret = "12345678901234567890";
    private static readonly byte[] Sha1SecretBytes = System.Text.Encoding.ASCII.GetBytes(Sha1Secret);

    [Theory]
    [InlineData(59L,          "94287082")]
    [InlineData(1111111109L,  "07081804")]
    [InlineData(1111111111L,  "14050471")]
    [InlineData(1234567890L,  "89005924")]
    [InlineData(2000000000L,  "69279037")]
    public void RFC6238_SHA1_8digit_vectors(long unixTime, string expected)
    {
        var t = DateTimeOffset.FromUnixTimeSeconds(unixTime);
        var code = Totp.Generate(Sha1SecretBytes, t,
            new Totp.Config(Totp.Algorithm.Sha1, Digits: 8, PeriodSeconds: 30));
        Assert.Equal(expected, code);
    }

    [Fact]
    public void Default_is_6_digits_30s()
    {
        var t = DateTimeOffset.FromUnixTimeSeconds(59);
        var code = Totp.Generate(Sha1SecretBytes, t);
        Assert.Equal(6, code.Length);
    }

    [Fact]
    public void Base32_round_trip()
    {
        var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11 };
        var encoded = Base32.Encode(data);
        var decoded = Base32.Decode(encoded);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void OtpAuth_uri_parses()
    {
        var (secret, cfg, issuer, account) = Totp.ParseUri(
            "otpauth://totp/GitHub:calin?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30");
        Assert.Equal("GitHub", issuer);
        Assert.Equal("calin", account);
        Assert.Equal(Totp.Algorithm.Sha1, cfg.Alg);
        Assert.Equal(6, cfg.Digits);
        Assert.Equal(30, cfg.PeriodSeconds);
        Assert.Equal(Base32.Decode("JBSWY3DPEHPK3PXP"), secret);
    }
}
