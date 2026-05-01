using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vault.Desktop;

public sealed class AppSettings
{
    public string? LastVaultPath { get; set; }
    public int AutoLockMinutes { get; set; } = 5;
    public int ClipboardClearSeconds { get; set; } = 30;
    public bool BackgroundSyncEnabled { get; set; } = false;
    public int BackgroundSyncIntervalMinutes { get; set; } = 5;

    [JsonIgnore]
    public TimeSpan AutoLockTimeout => TimeSpan.FromMinutes(Math.Max(1, AutoLockMinutes));

    [JsonIgnore]
    public TimeSpan ClipboardClearAfter => TimeSpan.FromSeconds(Math.Max(5, ClipboardClearSeconds));

    [JsonIgnore]
    public TimeSpan BackgroundSyncInterval => TimeSpan.FromMinutes(Math.Max(1, BackgroundSyncIntervalMinutes));

    public static string ConfigPath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "VaultCore");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "settings.json");
        }
    }

    public static AppSettings LoadOrDefault()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return new AppSettings();
            var json = File.ReadAllBytes(ConfigPath);
            return JsonSerializer.Deserialize(json, AppSettingsJsonContext.Default.AppSettings)
                   ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save()
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(this, AppSettingsJsonContext.Default.AppSettings);
        File.WriteAllBytes(ConfigPath, json);
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AppSettings))]
public partial class AppSettingsJsonContext : JsonSerializerContext { }
