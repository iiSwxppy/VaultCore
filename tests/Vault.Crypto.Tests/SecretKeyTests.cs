using Xunit;

namespace Vault.Crypto.Tests;

public class SecretKeyTests
{
    [Fact]
    public void Generate_is_parseable()
    {
        for (var i = 0; i < 100; i++)
        {
            var sk = SecretKey.Generate();
            Assert.True(SecretKey.TryParse(sk, out var normalized));
            Assert.Equal(sk, normalized);
        }
    }

    [Fact]
    public void Parse_handles_lowercase_and_extra_dashes()
    {
        var original = SecretKey.Generate();
        Assert.True(SecretKey.TryParse(original.ToLowerInvariant(), out var n1));
        Assert.Equal(original, n1);

        Assert.True(SecretKey.TryParse(original.Replace("-", " ", StringComparison.Ordinal), out var n2));
        Assert.Equal(original, n2);
    }

    [Fact]
    public void Parse_rejects_garbage()
    {
        Assert.False(SecretKey.TryParse("nope", out _));
        Assert.False(SecretKey.TryParse("", out _));
        Assert.False(SecretKey.TryParse("A1-OOOOOO-111111-222222-333333-444444-555555", out _)); // O and 1 not in alphabet
    }
}

public class PasswordGeneratorTests
{
    [Fact]
    public void Generates_requested_length()
    {
        var p = PasswordGenerator.Charset(new PasswordGenerator.CharsetOptions(Length: 32));
        Assert.Equal(32, p.Length);
    }

    [Fact]
    public void Includes_all_enabled_classes()
    {
        for (var i = 0; i < 50; i++)
        {
            var p = PasswordGenerator.Charset(new PasswordGenerator.CharsetOptions(
                Length: 16, UseLower: true, UseUpper: true, UseDigits: true, UseSymbols: true));
            Assert.Contains(p, char.IsLower);
            Assert.Contains(p, char.IsUpper);
            Assert.Contains(p, char.IsDigit);
            Assert.Contains(p, c => "!@#$%^&*()-_=+[]{};:,.<>/?".Contains(c, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Throws_if_no_class_enabled()
    {
        Assert.Throws<ArgumentException>(() =>
            PasswordGenerator.Charset(new PasswordGenerator.CharsetOptions(
                UseLower: false, UseUpper: false, UseDigits: false, UseSymbols: false)));
    }
}
