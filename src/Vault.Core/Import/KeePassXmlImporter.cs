using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using Vault.Core.Items;

namespace Vault.Core.Import;

/// <summary>
/// Imports KeePass XML 2.x exports.
///
/// Why XML and not .kdbx directly? KDBX 4 is a custom binary container with
/// AES-KDF or Argon2 + ChaCha20/AES — re-implementing it adds significant
/// surface area and uses GPL-licensed reference code. KeePass itself can
/// export to XML (File > Export > KeePass XML), so we ask the user to do
/// that one-time export and we import the cleartext XML.
///
/// Schema (simplified, KeePass 2.x):
///   &lt;KeePassFile&gt;
///     &lt;Root&gt;
///       &lt;Group&gt;
///         &lt;Name&gt;...&lt;/Name&gt;
///         &lt;Group&gt;...&lt;/Group&gt;        (recursive)
///         &lt;Entry&gt;
///           &lt;String&gt;
///             &lt;Key&gt;Title|UserName|Password|URL|Notes|...&lt;/Key&gt;
///             &lt;Value Protected="True"&gt;...&lt;/Value&gt;
///           &lt;/String&gt;
///         &lt;/Entry&gt;
///       &lt;/Group&gt;
///     &lt;/Root&gt;
///   &lt;/KeePassFile&gt;
///
/// Group nesting becomes flat tags in the imported item.
/// </summary>
public static class KeePassXmlImporter
{
    public static ImportReport ImportFromFile(string path, VaultSession session)
    {
        var doc = XDocument.Load(path, LoadOptions.None);
        return Import(doc, session);
    }

    public static ImportReport Import(XDocument doc, VaultSession session)
    {
        var warnings = new List<string>();
        var imported = 0;
        var total = 0;
        var skipped = 0;

        var root = doc.Element("KeePassFile")?.Element("Root");
        if (root is null) throw new InvalidDataException("Not a KeePass 2.x XML export (missing /KeePassFile/Root)");

        foreach (var entry in EnumerateEntries(root, groupPath: []))
        {
            total++;
            try
            {
                var payload = MapEntry(entry.Element, entry.GroupPath, warnings);
                if (payload is null) { skipped++; continue; }
                session.AddItem(payload);
                imported++;
            }
            catch (Exception ex)
            {
                warnings.Add($"Failed entry: {ex.Message}");
                skipped++;
            }
        }

        return new ImportReport(total, imported, skipped, warnings);
    }

    private static IEnumerable<(XElement Element, List<string> GroupPath)> EnumerateEntries(XElement group, List<string> groupPath)
    {
        var name = group.Element("Name")?.Value;
        var path = groupPath.ToList();
        if (!string.IsNullOrEmpty(name) && name != "Root") path.Add(name);

        foreach (var entry in group.Elements("Entry"))
        {
            yield return (entry, path);
        }

        foreach (var sub in group.Elements("Group"))
        {
            foreach (var sg in EnumerateEntries(sub, path))
                yield return sg;
        }
    }

    private static ItemPayload? MapEntry(XElement entry, List<string> groupPath, List<string> warnings)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in entry.Elements("String"))
        {
            var key = s.Element("Key")?.Value;
            var value = s.Element("Value")?.Value ?? "";
            if (!string.IsNullOrEmpty(key)) fields[key] = value;
        }

        var title = fields.GetValueOrDefault("Title") ?? "";
        var username = NullIfEmpty(fields.GetValueOrDefault("UserName"));
        var password = NullIfEmpty(fields.GetValueOrDefault("Password"));
        var url = NullIfEmpty(fields.GetValueOrDefault("URL"));
        var notes = NullIfEmpty(fields.GetValueOrDefault("Notes"));

        // KeePass uses TOTP plugins that store the secret in custom string fields.
        // Common conventions: "TOTP Seed", "otp", "TOTP".
        string? totp = null;
        foreach (var k in new[] { "TOTP Seed", "TOTP", "otp", "TOTP-Secret" })
        {
            if (fields.TryGetValue(k, out var v) && !string.IsNullOrWhiteSpace(v))
            {
                totp = v.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)
                    ? TryNormalizeOtpAuth(v) ?? v
                    : v.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
                break;
            }
        }

        // Custom string fields beyond the standard ones become CustomFields.
        var standard = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Title", "UserName", "Password", "URL", "Notes",
            "TOTP Seed", "TOTP", "otp", "TOTP-Secret",
        };
        var custom = fields
            .Where(kv => !standard.Contains(kv.Key) && !string.IsNullOrEmpty(kv.Value))
            .Select(kv => new CustomField(kv.Key, kv.Value, Concealed: false))
            .ToList();

        // Determine type. KeePass entries are all "logins" by convention. If
        // Password is set but Username/URL are not, it might be a generic note
        // or password-only entry — still import as Login (compatible).
        if (string.IsNullOrEmpty(title) && string.IsNullOrEmpty(username)
            && string.IsNullOrEmpty(password) && string.IsNullOrEmpty(url))
        {
            warnings.Add("Empty entry skipped");
            return null;
        }

        return new LoginPayload
        {
            Title = string.IsNullOrEmpty(title) ? "(untitled)" : title,
            Username = username,
            Password = password,
            Urls = url is null ? [] : [url],
            TotpSecret = totp,
            CustomFields = custom,
            Notes = notes,
            Tags = groupPath,
        };
    }

    private static string? NullIfEmpty(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s;

    private static string? TryNormalizeOtpAuth(string uri)
    {
        try
        {
            var (secret, _, _, _) = Crypto.Totp.ParseUri(uri);
            return Crypto.Base32.Encode(secret);
        }
        catch { return null; }
    }
}
