using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vault.Desktop.Services;

/// <summary>
/// Persistent log of failed unlock attempts. Used to rate-limit: after a
/// threshold of failures within a window, lock out further attempts for a
/// cooldown period.
///
/// Stored in user's local app data (not in the vault — vault is locked when
/// this matters). Plaintext: it only contains timestamps, no sensitive data.
/// </summary>
public sealed class FailedAttemptLog
{
    private const int MaxAttemptsBeforeLockout = 5;
    private static readonly TimeSpan AttemptWindow = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(5);

    private readonly string _path;
    private List<DateTimeOffset> _attempts;

    public FailedAttemptLog()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "VaultCore");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "unlock_attempts.json");
        _attempts = Load();
    }

    public void RecordFailure()
    {
        _attempts.Add(DateTimeOffset.UtcNow);
        Persist();
    }

    public void Reset()
    {
        _attempts.Clear();
        Persist();
    }

    /// <summary>
    /// Returns null if not locked out. Otherwise returns the time at which
    /// the next attempt may be made.
    /// </summary>
    public DateTimeOffset? LockoutUntil()
    {
        Trim();
        if (_attempts.Count < MaxAttemptsBeforeLockout) return null;
        var lastAttempt = _attempts[^1];
        var release = lastAttempt + LockoutDuration;
        return release > DateTimeOffset.UtcNow ? release : null;
    }

    public int RecentFailureCount()
    {
        Trim();
        return _attempts.Count;
    }

    private void Trim()
    {
        var cutoff = DateTimeOffset.UtcNow - AttemptWindow - LockoutDuration;
        _attempts.RemoveAll(t => t < cutoff);
    }

    private List<DateTimeOffset> Load()
    {
        try
        {
            if (!File.Exists(_path)) return [];
            var json = File.ReadAllBytes(_path);
            return JsonSerializer.Deserialize(json, FailedAttemptJsonContext.Default.ListDateTimeOffset) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private void Persist()
    {
        try
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(_attempts, FailedAttemptJsonContext.Default.ListDateTimeOffset);
            File.WriteAllBytes(_path, json);
        }
        catch
        {
            // Best effort — failed-attempt log is advisory, not security-critical.
        }
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(List<DateTimeOffset>))]
public partial class FailedAttemptJsonContext : JsonSerializerContext { }
