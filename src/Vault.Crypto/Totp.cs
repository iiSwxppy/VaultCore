using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Vault.Crypto;

/// <summary>
/// HOTP (RFC 4226) and TOTP (RFC 6238) implementation.
/// Supports SHA1/SHA256/SHA512, configurable digits and period.
/// Default = SHA1, 6 digits, 30s — what Google Authenticator uses.
/// </summary>
public static class Totp
{
    public enum Algorithm { Sha1, Sha256, Sha512 }

    public sealed record Config(Algorithm Alg = Algorithm.Sha1, int Digits = 6, int PeriodSeconds = 30);

    public static string Generate(ReadOnlySpan<byte> secret, DateTimeOffset utcNow, Config? cfg = null)
    {
        cfg ??= new Config();
        var counter = (long)Math.Floor((utcNow.ToUnixTimeSeconds()) / (double)cfg.PeriodSeconds);
        return Hotp(secret, counter, cfg);
    }

    public static int SecondsUntilNext(DateTimeOffset utcNow, int periodSeconds = 30)
    {
        var elapsed = (int)(utcNow.ToUnixTimeSeconds() % periodSeconds);
        return periodSeconds - elapsed;
    }

    public static string Hotp(ReadOnlySpan<byte> secret, long counter, Config cfg)
    {
        Span<byte> ctr = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(ctr, counter);

        Span<byte> hash = stackalloc byte[64];
        var written = cfg.Alg switch
        {
            Algorithm.Sha1 => HMACSHA1.HashData(secret, ctr, hash),
            Algorithm.Sha256 => HMACSHA256.HashData(secret, ctr, hash),
            Algorithm.Sha512 => HMACSHA512.HashData(secret, ctr, hash),
            _ => throw new ArgumentOutOfRangeException(nameof(cfg)),
        };
        var h = hash[..written];

        // Dynamic truncation (RFC 4226 §5.3)
        var offset = h[^1] & 0x0F;
        var bin =
            ((h[offset] & 0x7F) << 24) |
            ((h[offset + 1] & 0xFF) << 16) |
            ((h[offset + 2] & 0xFF) << 8) |
            (h[offset + 3] & 0xFF);

        var mod = (int)Math.Pow(10, cfg.Digits);
        var code = bin % mod;
        return code.ToString(System.Globalization.CultureInfo.InvariantCulture).PadLeft(cfg.Digits, '0');
    }

    /// <summary>
    /// Parse otpauth://totp/Label?secret=BASE32&issuer=...&algorithm=...&digits=...&period=...
    /// </summary>
    public static (byte[] Secret, Config Cfg, string? Issuer, string? Account) ParseUri(string otpauthUri)
    {
        var uri = new Uri(otpauthUri);
        if (uri.Scheme != "otpauth" || uri.Host != "totp") throw new ArgumentException("Not a TOTP URI");

        var label = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        string? issuer = null, account = label;
        var colon = label.IndexOf(':', StringComparison.Ordinal);
        if (colon > 0) { issuer = label[..colon]; account = label[(colon + 1)..].TrimStart(); }

        var query = ParseQuery(uri.Query);
        var secretB32 = query.GetValueOrDefault("secret") ?? throw new ArgumentException("Missing secret");
        var alg = (query.GetValueOrDefault("algorithm") ?? "SHA1").ToUpperInvariant() switch
        {
            "SHA1" => Algorithm.Sha1,
            "SHA256" => Algorithm.Sha256,
            "SHA512" => Algorithm.Sha512,
            _ => throw new ArgumentException("Unsupported algorithm"),
        };
        var digits = int.Parse(query.GetValueOrDefault("digits") ?? "6", System.Globalization.CultureInfo.InvariantCulture);
        var period = int.Parse(query.GetValueOrDefault("period") ?? "30", System.Globalization.CultureInfo.InvariantCulture);
        if (query.TryGetValue("issuer", out var queryIssuer) && !string.IsNullOrEmpty(queryIssuer)) issuer = queryIssuer;

        return (Base32.Decode(secretB32), new Config(alg, digits, period), issuer, account);
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return result;
        var q = query.StartsWith('?') ? query[1..] : query;
        foreach (var pair in q.Split('&'))
        {
            if (pair.Length == 0) continue;
            var eq = pair.IndexOf('=', StringComparison.Ordinal);
            if (eq < 0) result[Uri.UnescapeDataString(pair)] = "";
            else result[Uri.UnescapeDataString(pair[..eq])] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return result;
    }
}

public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static byte[] Decode(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var s = input.Replace(" ", "", StringComparison.Ordinal).TrimEnd('=').ToUpperInvariant();
        var output = new List<byte>(s.Length * 5 / 8);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var c in s)
        {
            var idx = Alphabet.IndexOf(c, StringComparison.Ordinal);
            if (idx < 0) throw new FormatException($"Invalid base32 char: {c}");
            buffer = (buffer << 5) | idx;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }
        return output.ToArray();
    }

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length + 4) / 5 * 8);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                sb.Append(Alphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }
        if (bitsLeft > 0) sb.Append(Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        return sb.ToString();
    }
}
