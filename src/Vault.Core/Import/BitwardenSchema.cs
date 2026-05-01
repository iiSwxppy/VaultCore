using System.Text.Json.Serialization;

namespace Vault.Core.Import;

/// <summary>
/// Bitwarden unencrypted JSON export schema (subset).
/// Source: https://bitwarden.com/help/export-your-data/
/// Only fields we actually map are declared; rest are ignored.
/// </summary>
public sealed class BitwardenExport
{
    [JsonPropertyName("encrypted")] public bool Encrypted { get; set; }
    [JsonPropertyName("folders")] public List<BitwardenFolder>? Folders { get; set; }
    [JsonPropertyName("items")] public List<BitwardenItem>? Items { get; set; }
}

public sealed class BitwardenFolder
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
}

public sealed class BitwardenItem
{
    // Bitwarden type codes: 1=login, 2=secure note, 3=card, 4=identity
    [JsonPropertyName("type")] public int Type { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
    [JsonPropertyName("folderId")] public string? FolderId { get; set; }
    [JsonPropertyName("login")] public BitwardenLogin? Login { get; set; }
    [JsonPropertyName("card")] public BitwardenCard? Card { get; set; }
    [JsonPropertyName("identity")] public BitwardenIdentity? Identity { get; set; }
    [JsonPropertyName("fields")] public List<BitwardenField>? Fields { get; set; }
}

public sealed class BitwardenLogin
{
    [JsonPropertyName("username")] public string? Username { get; set; }
    [JsonPropertyName("password")] public string? Password { get; set; }
    [JsonPropertyName("totp")] public string? Totp { get; set; }
    [JsonPropertyName("uris")] public List<BitwardenUri>? Uris { get; set; }
}

public sealed class BitwardenUri
{
    [JsonPropertyName("uri")] public string? Uri { get; set; }
}

public sealed class BitwardenCard
{
    [JsonPropertyName("cardholderName")] public string? CardholderName { get; set; }
    [JsonPropertyName("brand")] public string? Brand { get; set; }
    [JsonPropertyName("number")] public string? Number { get; set; }
    [JsonPropertyName("expMonth")] public string? ExpMonth { get; set; }
    [JsonPropertyName("expYear")] public string? ExpYear { get; set; }
    [JsonPropertyName("code")] public string? Code { get; set; }
}

public sealed class BitwardenIdentity
{
    [JsonPropertyName("firstName")] public string? FirstName { get; set; }
    [JsonPropertyName("lastName")] public string? LastName { get; set; }
    [JsonPropertyName("email")] public string? Email { get; set; }
    [JsonPropertyName("phone")] public string? Phone { get; set; }
    [JsonPropertyName("address1")] public string? Address1 { get; set; }
    [JsonPropertyName("city")] public string? City { get; set; }
    [JsonPropertyName("country")] public string? Country { get; set; }
    [JsonPropertyName("ssn")] public string? Ssn { get; set; }
    [JsonPropertyName("passportNumber")] public string? PassportNumber { get; set; }
}

public sealed class BitwardenField
{
    // 0=text, 1=hidden, 2=boolean, 3=linked
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("value")] public string? Value { get; set; }
    [JsonPropertyName("type")] public int Type { get; set; }
}
