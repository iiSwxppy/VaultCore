using System.Text.Json.Serialization;

namespace Vault.Ipc;

/// <summary>
/// Wire contract between browser extension, native host, and desktop app.
/// All messages are framed JSON. Same shape used over native-messaging stdio
/// AND over the named pipe to the desktop — the host is a transparent proxy.
///
/// Protocol version is included in every request so we can evolve safely.
/// </summary>
public sealed class IpcRequest
{
    [JsonPropertyName("v")]
    public int ProtocolVersion { get; set; } = 1;

    /// <summary>Client-generated correlation id, echoed in the response.</summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("type")]
    public string Type { get; set; } = "";

    /// <summary>For find_credentials: the page URL the user is on.</summary>
    [JsonPropertyName("url")]
    public string? Url { get; set; }

    /// <summary>For unlock_check: optional handshake field (no secret here, just a ping).</summary>
    [JsonPropertyName("origin")]
    public string? Origin { get; set; }

    /// <summary>For add_credential: title (defaults to host if not provided).</summary>
    [JsonPropertyName("title")]
    public string? Title { get; set; }

    /// <summary>For add_credential: username submitted on the form.</summary>
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    /// <summary>For add_credential: password submitted on the form.</summary>
    [JsonPropertyName("password")]
    public string? Password { get; set; }
}

public sealed class IpcResponse
{
    [JsonPropertyName("v")]
    public int ProtocolVersion { get; set; } = 1;

    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    /// <summary>Only set on successful find_credentials.</summary>
    [JsonPropertyName("credentials")]
    public List<CredentialMatch>? Credentials { get; set; }

    /// <summary>Set on status / unlock_check.</summary>
    [JsonPropertyName("unlocked")]
    public bool? Unlocked { get; set; }

    /// <summary>Set on get_totp.</summary>
    [JsonPropertyName("totpCode")]
    public string? TotpCode { get; set; }

    [JsonPropertyName("totpRemaining")]
    public int? TotpRemainingSeconds { get; set; }
}

public sealed class CredentialMatch
{
    [JsonPropertyName("itemId")]
    public string ItemId { get; set; } = "";

    [JsonPropertyName("title")]
    public string Title { get; set; } = "";

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }

    /// <summary>True if the item also has a TOTP secret (extension can fetch via get_totp).</summary>
    [JsonPropertyName("hasTotp")]
    public bool HasTotp { get; set; }
}

public static class IpcMessageTypes
{
    /// <summary>Health check / handshake. Returns unlocked status.</summary>
    public const string Status = "status";

    /// <summary>Find credential matches for a page URL.</summary>
    public const string FindCredentials = "find_credentials";

    /// <summary>Compute current TOTP code for an item by id.</summary>
    public const string GetTotp = "get_totp";

    /// <summary>Save a new login submitted from the extension.</summary>
    public const string AddCredential = "add_credential";
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(IpcRequest))]
[JsonSerializable(typeof(IpcResponse))]
[JsonSerializable(typeof(CredentialMatch))]
public partial class IpcJsonContext : JsonSerializerContext { }
