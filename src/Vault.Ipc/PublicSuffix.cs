using System.Reflection;

namespace Vault.Ipc;

/// <summary>
/// Public Suffix List based registrable-domain extraction.
///
/// PSL is the canonical answer to "what part of this hostname can register
/// cookies / be considered the same site?". E.g.:
///   accounts.google.com  → google.com (PSL says "com" is a public suffix)
///   bbc.co.uk            → bbc.co.uk  (PSL says "co.uk" is a public suffix)
///   bank.gov.au          → bank.gov.au
///   *.compute.amazonaws.com is a public suffix, so foo.bar.compute.amazonaws.com
///       has registrable bar.compute.amazonaws.com
///
/// We embed a snapshot of the PSL as a resource. It can grow stale; refresh
/// from https://publicsuffix.org/list/public_suffix_list.dat periodically.
/// For a personal password manager an annual refresh is fine.
///
/// The implementation is intentionally minimal: we only handle the rules
/// "exact match", "wildcard *", and "exception !". No IDN normalization
/// (we lowercase ASCII; punycode hostnames pass through unchanged, which is
/// acceptable for matching since both sides are lowered consistently).
/// </summary>
public static class PublicSuffix
{
    private static readonly HashSet<string> ExactRules;
    private static readonly HashSet<string> WildcardRules;
    private static readonly HashSet<string> ExceptionRules;

    static PublicSuffix()
    {
        ExactRules = new HashSet<string>(StringComparer.Ordinal);
        WildcardRules = new HashSet<string>(StringComparer.Ordinal);
        ExceptionRules = new HashSet<string>(StringComparer.Ordinal);

        using var stream = typeof(PublicSuffix).Assembly
            .GetManifestResourceStream("Vault.Ipc.public_suffix_list.dat");
        if (stream is null)
        {
            // Embedded resource not present (e.g. minimal build) — fall back to a
            // tiny built-in list of common TLDs. Better than nothing; the build
            // pipeline should embed the full PSL.
            foreach (var tld in MinimalFallbackTlds)
                ExactRules.Add(tld);
            return;
        }

        using var reader = new StreamReader(stream);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith("//", StringComparison.Ordinal))
                continue;

            // Split on whitespace and take the first token (PSL spec)
            var spaceIdx = trimmed.IndexOf(' ');
            if (spaceIdx > 0) trimmed = trimmed[..spaceIdx];

            if (trimmed.StartsWith('!'))
                ExceptionRules.Add(trimmed[1..]);
            else if (trimmed.StartsWith("*.", StringComparison.Ordinal))
                WildcardRules.Add(trimmed[2..]);
            else
                ExactRules.Add(trimmed);
        }
    }

    private static readonly string[] MinimalFallbackTlds =
    [
        "com", "net", "org", "io", "co", "uk", "co.uk", "de", "ro", "fr", "it",
        "es", "nl", "pl", "ru", "jp", "cn", "br", "in", "au", "ca", "us", "mx",
        "edu", "gov", "info", "biz", "dev", "app", "ai",
    ];

    /// <summary>
    /// Return the registrable domain ("eTLD+1") of a hostname.
    /// Examples:
    ///   "accounts.google.com"  -> "google.com"
    ///   "bbc.co.uk"            -> "bbc.co.uk"
    ///   "deep.sub.bbc.co.uk"   -> "bbc.co.uk"
    /// Returns null if the host IS a public suffix (no registrable part) or empty.
    /// </summary>
    public static string? GetRegistrableDomain(string hostname)
    {
        if (string.IsNullOrEmpty(hostname)) return null;
        var host = hostname.ToLowerInvariant().TrimEnd('.');
        var labels = host.Split('.');
        if (labels.Length < 2) return null;

        // Find the matching public suffix. Walk from broadest to narrowest:
        // We try suffixes of the host, longest first.
        var matchedSuffixLabels = 0;
        for (var i = 0; i < labels.Length; i++)
        {
            var candidate = string.Join('.', labels[i..]);

            // Exception beats anything: !foo.bar means foo.bar is NOT a public suffix.
            if (ExceptionRules.Contains(candidate))
            {
                // The suffix is candidate WITHOUT its first label.
                matchedSuffixLabels = labels.Length - i - 1;
                break;
            }

            if (ExactRules.Contains(candidate))
            {
                matchedSuffixLabels = labels.Length - i;
                break;
            }

            // Wildcard: *.foo.bar matches anything.foo.bar
            if (i + 1 < labels.Length)
            {
                var wildcardCandidate = string.Join('.', labels[(i + 1)..]);
                if (WildcardRules.Contains(wildcardCandidate))
                {
                    matchedSuffixLabels = labels.Length - i;
                    break;
                }
            }
        }

        if (matchedSuffixLabels == 0)
        {
            // No PSL match — assume last label is TLD. Fallback for unknowns.
            matchedSuffixLabels = 1;
        }

        // Need at least one label before the public suffix.
        if (labels.Length <= matchedSuffixLabels) return null;

        var registrable = labels.Length - matchedSuffixLabels - 1;
        return string.Join('.', labels[registrable..]);
    }

    /// <summary>True if two URLs share a registrable domain.</summary>
    public static bool SameSite(string urlA, string urlB)
    {
        var hostA = ExtractHost(urlA);
        var hostB = ExtractHost(urlB);
        if (hostA is null || hostB is null) return false;
        var regA = GetRegistrableDomain(hostA);
        var regB = GetRegistrableDomain(hostB);
        return regA is not null && string.Equals(regA, regB, StringComparison.Ordinal);
    }

    public static string? ExtractHost(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        var s = url.Trim();
        if (!s.Contains("://", StringComparison.Ordinal)) s = "https://" + s;
        return Uri.TryCreate(s, UriKind.Absolute, out var uri)
            ? uri.Host.ToLowerInvariant()
            : null;
    }
}
