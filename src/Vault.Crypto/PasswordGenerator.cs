using System.Security.Cryptography;
using System.Text;

namespace Vault.Crypto;

public static class PasswordGenerator
{
    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    private const string Symbols = "!@#$%^&*()-_=+[]{};:,.<>/?";
    private const string Ambiguous = "0Oo1lI";

    public sealed record CharsetOptions(
        int Length = 20,
        bool UseLower = true,
        bool UseUpper = true,
        bool UseDigits = true,
        bool UseSymbols = true,
        bool ExcludeAmbiguous = false);

    public static string Charset(CharsetOptions opt)
    {
        if (opt.Length is < 4 or > 256) throw new ArgumentOutOfRangeException(nameof(opt));

        var pool = new StringBuilder();
        if (opt.UseLower) pool.Append(Lower);
        if (opt.UseUpper) pool.Append(Upper);
        if (opt.UseDigits) pool.Append(Digits);
        if (opt.UseSymbols) pool.Append(Symbols);
        if (pool.Length == 0) throw new ArgumentException("At least one charset must be enabled");

        var poolStr = pool.ToString();
        if (opt.ExcludeAmbiguous)
        {
            var filtered = new StringBuilder();
            foreach (var c in poolStr)
                if (Ambiguous.IndexOf(c) < 0) filtered.Append(c);
            poolStr = filtered.ToString();
        }

        // Generate, then ensure each enabled class is present (rejection sample).
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var buf = new char[opt.Length];
            for (var i = 0; i < opt.Length; i++)
                buf[i] = poolStr[RandomNumberGenerator.GetInt32(poolStr.Length)];

            var s = new string(buf);
            if (opt.UseLower && !ContainsAny(s, Lower)) continue;
            if (opt.UseUpper && !ContainsAny(s, Upper)) continue;
            if (opt.UseDigits && !ContainsAny(s, Digits)) continue;
            if (opt.UseSymbols && !ContainsAny(s, Symbols)) continue;
            return s;
        }
        throw new InvalidOperationException("Could not satisfy charset constraints");
    }

    /// <summary>
    /// Diceware-style passphrase. Provide your own wordlist (EFF long list = 7776 words).
    /// </summary>
    public static string Passphrase(IReadOnlyList<string> wordlist, int wordCount = 6, char separator = '-', bool capitalize = false)
    {
        ArgumentNullException.ThrowIfNull(wordlist);
        if (wordlist.Count < 1024) throw new ArgumentException("Wordlist too small for safety", nameof(wordlist));
        if (wordCount is < 3 or > 32) throw new ArgumentOutOfRangeException(nameof(wordCount));

        var sb = new StringBuilder();
        for (var i = 0; i < wordCount; i++)
        {
            if (i > 0) sb.Append(separator);
            var w = wordlist[RandomNumberGenerator.GetInt32(wordlist.Count)];
            sb.Append(capitalize ? char.ToUpperInvariant(w[0]) + w[1..] : w);
        }
        return sb.ToString();
    }

    private static bool ContainsAny(string s, string chars)
    {
        foreach (var c in s) if (chars.IndexOf(c) >= 0) return true;
        return false;
    }
}
