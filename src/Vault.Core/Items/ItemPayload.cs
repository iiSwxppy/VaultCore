using System.Text.Json.Serialization;

namespace Vault.Core.Items;

public enum ItemType
{
    Login = 1,
    SecureNote = 2,
    CreditCard = 3,
    Identity = 4,
    SshKey = 5,
    TotpSeed = 6,
}

/// <summary>Discriminated union of decrypted item payloads.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "$type")]
[JsonDerivedType(typeof(LoginPayload), "login")]
[JsonDerivedType(typeof(SecureNotePayload), "note")]
[JsonDerivedType(typeof(CreditCardPayload), "card")]
[JsonDerivedType(typeof(IdentityPayload), "identity")]
[JsonDerivedType(typeof(SshKeyPayload), "ssh")]
[JsonDerivedType(typeof(TotpSeedPayload), "totp")]
public abstract record ItemPayload
{
    public string Title { get; init; } = "";
    public string? Notes { get; init; }
    public List<string> Tags { get; init; } = [];
}

public sealed record LoginPayload : ItemPayload
{
    public string? Username { get; init; }
    public string? Password { get; init; }
    public List<string> Urls { get; init; } = [];
    public string? TotpSecret { get; init; } // base32, optional inline
    public List<CustomField> CustomFields { get; init; } = [];
}

public sealed record SecureNotePayload : ItemPayload
{
    public string Body { get; init; } = "";
}

public sealed record CreditCardPayload : ItemPayload
{
    public string? Cardholder { get; init; }
    public string? Number { get; init; }
    public string? ExpiryMonth { get; init; }
    public string? ExpiryYear { get; init; }
    public string? Cvv { get; init; }
    public string? Pin { get; init; }
    public string? Brand { get; init; }
}

public sealed record IdentityPayload : ItemPayload
{
    public string? FullName { get; init; }
    public string? Email { get; init; }
    public string? Phone { get; init; }
    public string? Address { get; init; }
    public string? NationalId { get; init; }
    public string? PassportNumber { get; init; }
    public DateOnly? DateOfBirth { get; init; }
}

public sealed record SshKeyPayload : ItemPayload
{
    public string? PrivateKeyPem { get; init; }
    public string? PublicKey { get; init; }
    public string? Passphrase { get; init; }
    public string? KeyType { get; init; }
    public string? Fingerprint { get; init; }
}

public sealed record TotpSeedPayload : ItemPayload
{
    public string SecretBase32 { get; init; } = "";
    public string Algorithm { get; init; } = "SHA1";
    public int Digits { get; init; } = 6;
    public int Period { get; init; } = 30;
    public string? Issuer { get; init; }
    public string? Account { get; init; }
}

public sealed record CustomField(string Name, string Value, bool Concealed);
