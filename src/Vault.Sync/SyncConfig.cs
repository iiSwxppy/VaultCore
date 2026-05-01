using System.Text.Json.Serialization;

namespace Vault.Sync;

/// <summary>
/// S3-compatible remote configuration. Works with AWS S3, Backblaze B2 (via
/// S3-compatible endpoint), MinIO, Cloudflare R2, Wasabi, etc.
///
/// The access key and secret are stored locally next to the vault — they grant
/// access only to the bucket, not to the vault contents (vault is encrypted).
/// Still: use a bucket-scoped IAM policy, not root credentials.
/// </summary>
public sealed class SyncRemoteConfig
{
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = "";

    /// <summary>Region. Required by AWS, ignored by most S3-compatible services.</summary>
    [JsonPropertyName("region")]
    public string Region { get; set; } = "us-east-1";

    [JsonPropertyName("bucket")]
    public string Bucket { get; set; } = "";

    /// <summary>Object key (path) of the vault inside the bucket.</summary>
    [JsonPropertyName("key")]
    public string Key { get; set; } = "vault.bin";

    [JsonPropertyName("accessKeyId")]
    public string AccessKeyId { get; set; } = "";

    [JsonPropertyName("secretAccessKey")]
    public string SecretAccessKey { get; set; } = "";

    /// <summary>
    /// True for non-AWS S3 (MinIO, B2). AWS uses virtual-hosted-style by default;
    /// most third parties want path-style.
    /// </summary>
    [JsonPropertyName("forcePathStyle")]
    public bool ForcePathStyle { get; set; } = true;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Endpoint)) throw new ArgumentException("Endpoint required");
        if (string.IsNullOrWhiteSpace(Bucket)) throw new ArgumentException("Bucket required");
        if (string.IsNullOrWhiteSpace(Key)) throw new ArgumentException("Key required");
        if (string.IsNullOrWhiteSpace(AccessKeyId)) throw new ArgumentException("AccessKeyId required");
        if (string.IsNullOrWhiteSpace(SecretAccessKey)) throw new ArgumentException("SecretAccessKey required");
    }
}

/// <summary>
/// Sync state persisted locally next to the vault file (sibling .vault.sync file).
/// Contains the remote config + the ETag of the last successfully pushed
/// version, used for optimistic concurrency on next push.
/// </summary>
public sealed class SyncState
{
    [JsonPropertyName("remote")]
    public SyncRemoteConfig Remote { get; set; } = new();

    /// <summary>ETag of the remote object at last successful sync. Used for if-match on next push.</summary>
    [JsonPropertyName("lastKnownETag")]
    public string? LastKnownETag { get; set; }

    [JsonPropertyName("lastSyncedAt")]
    public DateTimeOffset? LastSyncedAt { get; set; }
}

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(SyncState))]
[JsonSerializable(typeof(SyncRemoteConfig))]
public partial class SyncJsonContext : JsonSerializerContext { }
