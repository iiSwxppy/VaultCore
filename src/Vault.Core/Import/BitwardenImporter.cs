using System.Text.Json;
using Vault.Core.Items;
using Vault.Core.Serialization;

namespace Vault.Core.Import;

public sealed record ImportReport(
    int TotalRead,
    int Imported,
    int Skipped,
    List<string> Warnings);

public static class BitwardenImporter
{
    public static ImportReport ImportFromFile(string path, VaultSession session)
    {
        var json = File.ReadAllBytes(path);
        return Import(json, session);
    }

    public static ImportReport Import(ReadOnlySpan<byte> json, VaultSession session)
    {
        var export = JsonSerializer.Deserialize(json, VaultJsonContext.Default.BitwardenExport)
            ?? throw new InvalidDataException("Empty Bitwarden export");

        if (export.Encrypted)
            throw new NotSupportedException("Encrypted Bitwarden exports are not supported. Export as JSON (unencrypted).");

        var warnings = new List<string>();
        var folders = (export.Folders ?? []).ToDictionary(f => f.Id ?? "", f => f.Name ?? "");
        var items = export.Items ?? [];
        var imported = 0;
        var skipped = 0;

        foreach (var bw in items)
        {
            var tags = new List<string>();
            if (!string.IsNullOrEmpty(bw.FolderId) && folders.TryGetValue(bw.FolderId, out var folderName) && !string.IsNullOrEmpty(folderName))
                tags.Add(folderName);

            ItemPayload? payload = bw.Type switch
            {
                1 => MapLogin(bw, tags),
                2 => new SecureNotePayload { Title = bw.Name ?? "", Body = bw.Notes ?? "", Notes = null, Tags = tags },
                3 => MapCard(bw, tags),
                4 => MapIdentity(bw, tags),
                _ => null,
            };

            if (payload is null)
            {
                warnings.Add($"Skipped item '{bw.Name}': unsupported type {bw.Type}");
                skipped++;
                continue;
            }

            session.AddItem(payload);
            imported++;
        }

        return new ImportReport(items.Count, imported, skipped, warnings);
    }

    private static LoginPayload MapLogin(BitwardenItem bw, List<string> tags)
    {
        var login = bw.Login;
        var urls = login?.Uris?.Select(u => u.Uri).Where(u => !string.IsNullOrEmpty(u)).Cast<string>().ToList() ?? [];

        // Bitwarden TOTP can be a raw base32 secret OR an otpauth:// URI. Normalize.
        string? totpSecret = null;
        if (!string.IsNullOrEmpty(login?.Totp))
        {
            if (login.Totp.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var (secret, _, _, _) = Crypto.Totp.ParseUri(login.Totp);
                    totpSecret = Crypto.Base32.Encode(secret);
                }
                catch { /* leave null */ }
            }
            else totpSecret = login.Totp;
        }

        var customFields = (bw.Fields ?? [])
            .Where(f => !string.IsNullOrEmpty(f.Name) && !string.IsNullOrEmpty(f.Value))
            .Select(f => new CustomField(f.Name!, f.Value!, Concealed: f.Type == 1))
            .ToList();

        var notes = string.IsNullOrEmpty(bw.Notes) ? null : bw.Notes;

        return new LoginPayload
        {
            Title = bw.Name ?? "",
            Username = login?.Username,
            Password = login?.Password,
            Urls = urls,
            TotpSecret = totpSecret,
            CustomFields = customFields,
            Notes = notes,
            Tags = tags,
        };
    }

    private static CreditCardPayload MapCard(BitwardenItem bw, List<string> tags)
    {
        var c = bw.Card;
        return new CreditCardPayload
        {
            Title = bw.Name ?? "",
            Cardholder = c?.CardholderName,
            Number = c?.Number,
            ExpiryMonth = c?.ExpMonth,
            ExpiryYear = c?.ExpYear,
            Cvv = c?.Code,
            Brand = c?.Brand,
            Notes = string.IsNullOrEmpty(bw.Notes) ? null : bw.Notes,
            Tags = tags,
        };
    }

    private static IdentityPayload MapIdentity(BitwardenItem bw, List<string> tags)
    {
        var i = bw.Identity;
        var fullName = string.Join(" ",
            new[] { i?.FirstName, i?.LastName }.Where(s => !string.IsNullOrEmpty(s))).Trim();
        var address = string.Join(", ",
            new[] { i?.Address1, i?.City, i?.Country }.Where(s => !string.IsNullOrEmpty(s)));

        return new IdentityPayload
        {
            Title = bw.Name ?? "",
            FullName = string.IsNullOrEmpty(fullName) ? null : fullName,
            Email = i?.Email,
            Phone = i?.Phone,
            Address = string.IsNullOrEmpty(address) ? null : address,
            NationalId = i?.Ssn,
            PassportNumber = i?.PassportNumber,
            Notes = string.IsNullOrEmpty(bw.Notes) ? null : bw.Notes,
            Tags = tags,
        };
    }
}
