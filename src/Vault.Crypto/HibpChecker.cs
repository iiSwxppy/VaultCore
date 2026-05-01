using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace Vault.Crypto;

/// <summary>
/// Have I Been Pwned password breach check using k-anonymity.
///
/// Sends only the first 5 chars of SHA1(password) to api.pwnedpasswords.com.
/// HIBP returns ~500 hash suffixes that share that prefix. We check locally
/// whether OUR full hash is among them. The full password and full hash
/// never leave the client.
///
/// API spec: https://haveibeenpwned.com/API/v3#PwnedPasswords
/// </summary>
public sealed class HibpChecker
{
    private const string ApiBase = "https://api.pwnedpasswords.com/range/";
    private readonly HttpClient _http;

    public HibpChecker(HttpClient? http = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("VaultCore/1.0");
        // Opt-in to padding: HIBP pads response so all responses are similar size,
        // preventing traffic analysis attacks.
        _http.DefaultRequestHeaders.Add("Add-Padding", "true");
    }

    /// <summary>
    /// Returns the breach count for this password, or 0 if not found.
    /// Throws on network failure.
    /// </summary>
    public async Task<int> CheckPasswordAsync(string password, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        var hashHex = ComputeSha1Hex(password);
        var prefix = hashHex[..5];
        var suffix = hashHex[5..];

        using var resp = await _http.GetAsync(ApiBase + prefix, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        // Body lines: "SUFFIX:COUNT\r\n". Padded entries have count 0.
        foreach (var line in body.Split('\n'))
        {
            var trimmed = line.AsSpan().Trim();
            if (trimmed.IsEmpty) continue;
            var colon = trimmed.IndexOf(':');
            if (colon < 0) continue;
            var lineSuffix = trimmed[..colon];
            if (lineSuffix.Equals(suffix, StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(trimmed[(colon + 1)..],
                    System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var count))
                {
                    return count;
                }
            }
        }
        return 0;
    }

    private static string ComputeSha1Hex(string password)
    {
        Span<byte> hash = stackalloc byte[20];
        var pwBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            SHA1.HashData(pwBytes, hash);
            return Convert.ToHexString(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwBytes);
        }
    }
}
