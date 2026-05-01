using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

namespace Vault.Sync;

/// <summary>
/// Thin wrapper around AWS S3 SDK for the operations vault sync needs.
///
/// Operations:
///   - Pull: download object body + ETag.
///   - Push: upload object, optionally with If-Match ETag for optimistic concurrency.
///   - Head: get current ETag without downloading body.
///
/// All errors surface as <see cref="SyncException"/> with categorized causes,
/// so callers can react to "remote changed under us" specifically.
/// </summary>
public sealed class S3VaultRemote : IDisposable
{
    private readonly IAmazonS3 _client;
    private readonly SyncRemoteConfig _config;
    private bool _disposed;

    public S3VaultRemote(SyncRemoteConfig config)
    {
        config.Validate();
        _config = config;

        var s3Config = new AmazonS3Config
        {
            ServiceURL = config.Endpoint,
            ForcePathStyle = config.ForcePathStyle,
            AuthenticationRegion = config.Region,
            // Disable AWS-specific behaviors that break against MinIO/B2.
            UseHttp = config.Endpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase),
        };
        // Don't set RegionEndpoint when ServiceURL is provided — they conflict.
        // The SDK uses ServiceURL alone for the actual HTTP call; AuthenticationRegion
        // governs the SigV4 signing region. AWS-only config skips ServiceURL.

        _client = new AmazonS3Client(
            new BasicAWSCredentials(config.AccessKeyId, config.SecretAccessKey),
            s3Config);
    }

    /// <summary>Returns null if the object doesn't exist. Throws on auth/network errors.</summary>
    public async Task<string?> HeadETagAsync(CancellationToken ct = default)
    {
        try
        {
            var resp = await _client.GetObjectMetadataAsync(_config.Bucket, _config.Key, ct).ConfigureAwait(false);
            return Normalize(resp.ETag);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
        catch (AmazonS3Exception ex)
        {
            throw Categorize(ex);
        }
    }

    /// <summary>
    /// Download the remote object body. Returns (bytes, etag).
    /// Throws RemoteNotFoundException if the object doesn't exist.
    /// </summary>
    public async Task<(byte[] Body, string ETag)> PullAsync(CancellationToken ct = default)
    {
        try
        {
            var req = new GetObjectRequest { BucketName = _config.Bucket, Key = _config.Key };
            using var resp = await _client.GetObjectAsync(req, ct).ConfigureAwait(false);
            using var ms = new MemoryStream();
            await resp.ResponseStream.CopyToAsync(ms, ct).ConfigureAwait(false);
            return (ms.ToArray(), Normalize(resp.ETag) ?? "");
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            throw new RemoteNotFoundException("No vault file at the configured remote location.", ex);
        }
        catch (AmazonS3Exception ex)
        {
            throw Categorize(ex);
        }
    }

    /// <summary>
    /// Upload the vault. If <paramref name="ifMatchETag"/> is provided and the
    /// current remote ETag doesn't match, throws RemoteChangedException so the
    /// caller can pull, merge, and retry.
    ///
    /// Note: not all S3-compatible services support If-Match on PUT. We do a
    /// HEAD first and compare, then PUT. This is racy in theory (TOCTOU window)
    /// but acceptable for single-user multi-device — a miss only leads to an
    /// extra round of pull-merge-push, not data loss (the AEAD-protected file
    /// has an HMAC).
    /// </summary>
    public async Task<string> PushAsync(byte[] body, string? ifMatchETag, CancellationToken ct = default)
    {
        try
        {
            if (ifMatchETag is not null)
            {
                var current = await HeadETagAsync(ct).ConfigureAwait(false);
                if (current is not null && current != ifMatchETag)
                {
                    throw new RemoteChangedException(
                        $"Remote ETag changed (expected {ifMatchETag}, got {current}). Pull and merge.");
                }
                if (current is null && ifMatchETag.Length > 0)
                {
                    // Remote disappeared under us. Treat as conflict — caller should re-evaluate.
                    throw new RemoteChangedException("Remote object disappeared.");
                }
            }

            var req = new PutObjectRequest
            {
                BucketName = _config.Bucket,
                Key = _config.Key,
                InputStream = new MemoryStream(body),
                ContentType = "application/octet-stream",
                AutoCloseStream = true,
                DisablePayloadSigning = false,
            };

            var resp = await _client.PutObjectAsync(req, ct).ConfigureAwait(false);
            return Normalize(resp.ETag) ?? throw new SyncException("Server did not return ETag.");
        }
        catch (RemoteChangedException) { throw; }
        catch (AmazonS3Exception ex)
        {
            throw Categorize(ex);
        }
    }

    private static string? Normalize(string? etag) =>
        string.IsNullOrEmpty(etag) ? null : etag.Trim('"');

    private static SyncException Categorize(AmazonS3Exception ex) => ex.StatusCode switch
    {
        System.Net.HttpStatusCode.Forbidden =>
            new SyncException($"Access denied (403). Check IAM policy on bucket '{ex.Message}'.", ex),
        System.Net.HttpStatusCode.NotFound =>
            new RemoteNotFoundException("Bucket or object not found.", ex),
        System.Net.HttpStatusCode.Unauthorized =>
            new SyncException("Invalid credentials.", ex),
        _ => new SyncException($"S3 error {ex.StatusCode}: {ex.Message}", ex),
    };

    public void Dispose()
    {
        if (_disposed) return;
        _client.Dispose();
        _disposed = true;
    }
}

public class SyncException : Exception
{
    public SyncException(string message, Exception? inner = null) : base(message, inner) { }
}

public sealed class RemoteNotFoundException : SyncException
{
    public RemoteNotFoundException(string message, Exception? inner = null) : base(message, inner) { }
}

public sealed class RemoteChangedException : SyncException
{
    public RemoteChangedException(string message, Exception? inner = null) : base(message, inner) { }
}
