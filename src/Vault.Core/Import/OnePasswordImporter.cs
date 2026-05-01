using System.IO.Compression;
using System.Text.Json;
using Vault.Core.Items;

namespace Vault.Core.Import;

/// <summary>
/// 1Password 1pux import.
///
/// A .1pux file is a ZIP archive containing:
///   export.attributes      JSON metadata about the export
///   export.data            JSON with all account/vault/item data
///   files/...              attachments (we don't import these for now)
///
/// The schema is undocumented but stable. We parse loosely with JsonNode
/// instead of strongly typed records — too many shape variations across versions.
/// </summary>
public static class OnePasswordImporter
{
    public static ImportReport ImportFromFile(string archivePath, VaultSession session)
    {
        using var fs = File.OpenRead(archivePath);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Read);
        var dataEntry = zip.GetEntry("export.data")
            ?? throw new InvalidDataException("Not a 1pux file: missing export.data");

        using var stream = dataEntry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var json = JsonDocument.Parse(ms.ToArray());

        var warnings = new List<string>();
        var imported = 0;
        var skipped = 0;
        var total = 0;

        // Path: accounts[].vaults[].items[]
        if (!json.RootElement.TryGetProperty("accounts", out var accounts))
            throw new InvalidDataException("Bad 1pux: no accounts");

        foreach (var account in accounts.EnumerateArray())
        {
            if (!account.TryGetProperty("vaults", out var vaults)) continue;
            foreach (var vault in vaults.EnumerateArray())
            {
                var vaultName = vault.TryGetProperty("attrs", out var attrs)
                    && attrs.TryGetProperty("name", out var n)
                    ? n.GetString() : null;

                if (!vault.TryGetProperty("items", out var items)) continue;
                foreach (var item in items.EnumerateArray())
                {
                    total++;
                    try
                    {
                        var payload = MapItem(item, vaultName, warnings);
                        if (payload is null) { skipped++; continue; }
                        session.AddItem(payload);
                        imported++;
                    }
                    catch (Exception ex)
                    {
                        warnings.Add($"Failed item: {ex.Message}");
                        skipped++;
                    }
                }
            }
        }

        return new ImportReport(total, imported, skipped, warnings);
    }

    private static ItemPayload? MapItem(JsonElement item, string? vaultName, List<string> warnings)
    {
        // Top-level item structure in 1pux:
        // { "uuid": "...", "favIndex": 0, "createdAt": ..., "updatedAt": ...,
        //   "trashed": false, "categoryUuid": "001", "details": {...}, "overview": {...} }
        if (item.TryGetProperty("trashed", out var tr) && tr.ValueKind == JsonValueKind.True)
            return null;

        var category = item.TryGetProperty("categoryUuid", out var cat) ? cat.GetString() : null;
        var overview = item.TryGetProperty("overview", out var ov) ? ov : default;
        var details = item.TryGetProperty("details", out var de) ? de : default;

        var title = overview.ValueKind == JsonValueKind.Object && overview.TryGetProperty("title", out var t)
            ? t.GetString() ?? "" : "";

        var notes = details.ValueKind == JsonValueKind.Object && details.TryGetProperty("notesPlain", out var np)
            ? np.GetString() : null;

        var tags = new List<string>();
        if (!string.IsNullOrEmpty(vaultName)) tags.Add(vaultName);
        if (overview.ValueKind == JsonValueKind.Object && overview.TryGetProperty("tags", out var tgs)
            && tgs.ValueKind == JsonValueKind.Array)
        {
            foreach (var tag in tgs.EnumerateArray())
                if (tag.GetString() is { } s) tags.Add(s);
        }

        // 1Password category UUIDs:
        //   001 Login, 002 CreditCard, 003 SecureNote, 004 Identity, 005 Password,
        //   006 Document, 100 SoftwareLicense, 101 BankAccount, 102 Database,
        //   103 DriversLicense, 104 OutdoorLicense, 105 Membership, 106 Passport,
        //   107 RewardProgram, 108 SocialSecurityNumber, 109 WirelessRouter,
        //   110 Server, 111 EmailAccount, 112 API_Credential, 113 MedicalRecord,
        //   114 SshKey
        return category switch
        {
            "001" => MapLogin(title, notes, tags, overview, details),
            "003" => new SecureNotePayload { Title = title, Body = notes ?? "", Notes = null, Tags = tags },
            "002" => MapCard(title, notes, tags, details),
            "004" => MapIdentity(title, notes, tags, details),
            "005" => MapStandalonePassword(title, notes, tags, details),
            "114" => MapSshKey(title, notes, tags, details),
            _ => FallbackToNote(title, notes, tags, details, category, warnings),
        };
    }

    private static LoginPayload MapLogin(string title, string? notes, List<string> tags, JsonElement overview, JsonElement details)
    {
        string? username = null, password = null, totpSecret = null;
        var urls = new List<string>();
        var custom = new List<CustomField>();

        if (overview.ValueKind == JsonValueKind.Object && overview.TryGetProperty("url", out var url) && url.GetString() is { } u)
            urls.Add(u);
        if (overview.ValueKind == JsonValueKind.Object && overview.TryGetProperty("urls", out var urlList) && urlList.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in urlList.EnumerateArray())
                if (x.TryGetProperty("url", out var v) && v.GetString() is { } s && !urls.Contains(s)) urls.Add(s);
        }

        if (details.ValueKind == JsonValueKind.Object)
        {
            // Login fields are in details.loginFields[] with designation="username"|"password"
            if (details.TryGetProperty("loginFields", out var lf) && lf.ValueKind == JsonValueKind.Array)
            {
                foreach (var field in lf.EnumerateArray())
                {
                    var designation = field.TryGetProperty("designation", out var d) ? d.GetString() : null;
                    var value = field.TryGetProperty("value", out var v) ? v.GetString() : null;
                    if (string.IsNullOrEmpty(value)) continue;
                    if (designation == "username") username = value;
                    else if (designation == "password") password = value;
                }
            }
            // Section fields can contain TOTP and arbitrary custom fields.
            if (details.TryGetProperty("sections", out var sections) && sections.ValueKind == JsonValueKind.Array)
            {
                foreach (var section in sections.EnumerateArray())
                {
                    if (!section.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Array) continue;
                    foreach (var f in fields.EnumerateArray())
                    {
                        var fieldType = f.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Object
                            ? v.EnumerateObject().FirstOrDefault().Name : null;
                        var rawVal = v.ValueKind == JsonValueKind.Object && fieldType != null
                            && v.TryGetProperty(fieldType, out var rv) ? rv.GetString() : null;
                        var fieldTitle = f.TryGetProperty("title", out var ft) ? ft.GetString() : null;

                        if (fieldType == "totp" && !string.IsNullOrEmpty(rawVal))
                        {
                            totpSecret = NormalizeTotp(rawVal);
                        }
                        else if (!string.IsNullOrEmpty(rawVal) && !string.IsNullOrEmpty(fieldTitle))
                        {
                            var concealed = fieldType == "concealed";
                            custom.Add(new CustomField(fieldTitle, rawVal, concealed));
                        }
                    }
                }
            }
        }

        return new LoginPayload
        {
            Title = title,
            Username = username,
            Password = password,
            Urls = urls,
            TotpSecret = totpSecret,
            CustomFields = custom,
            Notes = notes,
            Tags = tags,
        };
    }

    private static SecureNotePayload MapStandalonePassword(string title, string? notes, List<string> tags, JsonElement details)
    {
        // 1Password category 005 = standalone password. Treat as login with no username.
        string? password = null;
        if (details.ValueKind == JsonValueKind.Object && details.TryGetProperty("password", out var p))
            password = p.GetString();
        return new SecureNotePayload
        {
            Title = title,
            Body = $"Password: {password ?? "(empty)"}\n\n{notes ?? ""}",
            Tags = tags,
        };
    }

    private static CreditCardPayload MapCard(string title, string? notes, List<string> tags, JsonElement details)
    {
        string? cardholder = null, number = null, cvv = null, brand = null, expMonth = null, expYear = null;
        if (details.ValueKind == JsonValueKind.Object && details.TryGetProperty("sections", out var sections))
        {
            foreach (var section in sections.EnumerateArray())
            {
                if (!section.TryGetProperty("fields", out var fields)) continue;
                foreach (var f in fields.EnumerateArray())
                {
                    var id = f.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
                    var v = f.TryGetProperty("value", out var ve) ? ve : default;
                    if (v.ValueKind != JsonValueKind.Object) continue;
                    var inner = v.EnumerateObject().FirstOrDefault();
                    var s = inner.Value.ValueKind == JsonValueKind.String ? inner.Value.GetString() : inner.Value.GetRawText();

                    switch (id)
                    {
                        case "cardholder": cardholder = s; break;
                        case "ccnum" or "number": number = s; break;
                        case "cvv": cvv = s; break;
                        case "type": brand = s; break;
                        case "expiry":
                            // 1Password stores expiry as YYYYMM string (e.g., "202708")
                            if (!string.IsNullOrEmpty(s) && s.Length >= 6)
                            {
                                expYear = s[..4];
                                expMonth = s[4..6];
                            }
                            break;
                    }
                }
            }
        }
        return new CreditCardPayload
        {
            Title = title,
            Cardholder = cardholder,
            Number = number,
            Cvv = cvv,
            Brand = brand,
            ExpiryMonth = expMonth,
            ExpiryYear = expYear,
            Notes = notes,
            Tags = tags,
        };
    }

    private static IdentityPayload MapIdentity(string title, string? notes, List<string> tags, JsonElement details)
    {
        // Identity is field-heavy. Concatenate non-empty strings for free-form fields.
        string? fullName = null, email = null, phone = null, address = null;
        if (details.ValueKind == JsonValueKind.Object && details.TryGetProperty("sections", out var sections))
        {
            foreach (var section in sections.EnumerateArray())
            {
                if (!section.TryGetProperty("fields", out var fields)) continue;
                foreach (var f in fields.EnumerateArray())
                {
                    var id = f.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
                    var v = f.TryGetProperty("value", out var ve) ? ve : default;
                    if (v.ValueKind != JsonValueKind.Object) continue;
                    var inner = v.EnumerateObject().FirstOrDefault();
                    var s = inner.Value.ValueKind == JsonValueKind.String ? inner.Value.GetString() : null;
                    switch (id)
                    {
                        case "firstname" or "lastname":
                            fullName = string.IsNullOrEmpty(fullName) ? s : $"{fullName} {s}";
                            break;
                        case "email": email = s; break;
                        case "defphone" or "homephone" or "cellphone": phone ??= s; break;
                        case "address": address = s; break;
                    }
                }
            }
        }
        return new IdentityPayload
        {
            Title = title,
            FullName = fullName,
            Email = email,
            Phone = phone,
            Address = address,
            Notes = notes,
            Tags = tags,
        };
    }

    private static SshKeyPayload MapSshKey(string title, string? notes, List<string> tags, JsonElement details)
    {
        string? privKey = null, pubKey = null, fingerprint = null, keyType = null, passphrase = null;
        if (details.ValueKind == JsonValueKind.Object)
        {
            if (details.TryGetProperty("privateKey", out var pk)) privKey = pk.GetString();
            if (details.TryGetProperty("publicKey", out var pubk)) pubKey = pubk.GetString();
            if (details.TryGetProperty("fingerprint", out var fp)) fingerprint = fp.GetString();
            if (details.TryGetProperty("keyType", out var kt)) keyType = kt.GetString();
        }
        return new SshKeyPayload
        {
            Title = title,
            PrivateKeyPem = privKey,
            PublicKey = pubKey,
            Fingerprint = fingerprint,
            KeyType = keyType,
            Passphrase = passphrase,
            Notes = notes,
            Tags = tags,
        };
    }

    private static SecureNotePayload FallbackToNote(string title, string? notes, List<string> tags, JsonElement details,
        string? category, List<string> warnings)
    {
        warnings.Add($"Item '{title}' (category {category}): no specific mapping, imported as secure note");
        var body = new System.Text.StringBuilder();
        if (!string.IsNullOrEmpty(notes)) body.AppendLine(notes);
        if (details.ValueKind == JsonValueKind.Object)
        {
            body.AppendLine();
            body.AppendLine("--- Imported fields ---");
            body.AppendLine(details.GetRawText());
        }
        return new SecureNotePayload { Title = title, Body = body.ToString(), Tags = tags };
    }

    private static string? NormalizeTotp(string raw)
    {
        if (raw.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var (secret, _, _, _) = Crypto.Totp.ParseUri(raw);
                return Crypto.Base32.Encode(secret);
            }
            catch { return null; }
        }
        return raw;
    }
}
