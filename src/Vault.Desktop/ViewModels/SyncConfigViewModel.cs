using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Vault.Sync;

namespace Vault.Desktop.ViewModels;

/// <summary>
/// Configure the S3-compatible remote without dropping to CLI. Loads existing
/// values if a sync state file is already present.
///
/// The secret access key is the only sensitive field. We don't display it
/// after first save (show "********") to avoid shoulder-surfing on edit;
/// user types a new value to replace it, leaves blank to keep existing.
/// </summary>
public sealed partial class SyncConfigViewModel : ViewModelBase
{
    private readonly string _vaultPath;
    private readonly string? _existingSecretKey;

    [ObservableProperty] private string _endpoint = "";
    [ObservableProperty] private string _region = "us-east-1";
    [ObservableProperty] private string _bucket = "";
    [ObservableProperty] private string _objectKey = "vault.bin";
    [ObservableProperty] private string _accessKeyId = "";
    [ObservableProperty] private string _secretAccessKey = "";
    [ObservableProperty] private bool _forcePathStyle = true;
    [ObservableProperty] private string? _validationError;
    [ObservableProperty] private bool _isExisting;
    [ObservableProperty] private string? _testResult;
    [ObservableProperty] private bool _isTesting;

    public bool Saved { get; private set; }
    public event EventHandler? CloseRequested;

    public SyncConfigViewModel(string vaultPath)
    {
        _vaultPath = vaultPath;
        var orch = new SyncOrchestrator(vaultPath);
        if (orch.HasConfig)
        {
            try
            {
                var state = orch.LoadState();
                _endpoint = state.Remote.Endpoint;
                _region = state.Remote.Region;
                _bucket = state.Remote.Bucket;
                _objectKey = state.Remote.Key;
                _accessKeyId = state.Remote.AccessKeyId;
                _existingSecretKey = state.Remote.SecretAccessKey;
                _secretAccessKey = ""; // empty placeholder; "" means "keep existing"
                _forcePathStyle = state.Remote.ForcePathStyle;
                _isExisting = true;
            }
            catch (Exception ex)
            {
                _validationError = $"Existing config could not be loaded: {ex.Message}";
            }
        }
    }

    [RelayCommand]
    private void Save()
    {
        if (string.IsNullOrWhiteSpace(Endpoint)) { ValidationError = "Endpoint is required."; return; }
        if (string.IsNullOrWhiteSpace(Bucket)) { ValidationError = "Bucket is required."; return; }
        if (string.IsNullOrWhiteSpace(ObjectKey)) { ValidationError = "Object key is required."; return; }
        if (string.IsNullOrWhiteSpace(AccessKeyId)) { ValidationError = "Access key ID is required."; return; }

        var effectiveSecret = string.IsNullOrEmpty(SecretAccessKey)
            ? _existingSecretKey ?? ""
            : SecretAccessKey;
        if (string.IsNullOrEmpty(effectiveSecret))
        {
            ValidationError = "Secret access key is required.";
            return;
        }

        var config = new SyncRemoteConfig
        {
            Endpoint = Endpoint.Trim(),
            Region = string.IsNullOrWhiteSpace(Region) ? "us-east-1" : Region.Trim(),
            Bucket = Bucket.Trim(),
            Key = ObjectKey.Trim(),
            AccessKeyId = AccessKeyId.Trim(),
            SecretAccessKey = effectiveSecret,
            ForcePathStyle = ForcePathStyle,
        };

        try
        {
            new SyncOrchestrator(_vaultPath).ConfigureRemote(config);
            Saved = true;
            CloseRequested?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            ValidationError = ex.Message;
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        Saved = false;
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Try a HEAD request against the bucket+key. Doesn't error on 404 — that
    /// just means "no vault uploaded yet", which is fine. Errors on auth,
    /// network, or wrong endpoint.
    /// </summary>
    [RelayCommand]
    private async Task TestConnection()
    {
        TestResult = null;
        IsTesting = true;
        try
        {
            var effectiveSecret = string.IsNullOrEmpty(SecretAccessKey)
                ? _existingSecretKey ?? ""
                : SecretAccessKey;

            var config = new SyncRemoteConfig
            {
                Endpoint = Endpoint.Trim(),
                Region = string.IsNullOrWhiteSpace(Region) ? "us-east-1" : Region.Trim(),
                Bucket = Bucket.Trim(),
                Key = ObjectKey.Trim(),
                AccessKeyId = AccessKeyId.Trim(),
                SecretAccessKey = effectiveSecret,
                ForcePathStyle = ForcePathStyle,
            };
            config.Validate();

            using var remote = new S3VaultRemote(config);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var etag = await remote.HeadETagAsync(cts.Token);
            TestResult = etag is null
                ? "OK — bucket reachable; no vault file yet (will be created on first sync)."
                : $"OK — bucket reachable. Remote ETag: {etag}";
        }
        catch (Exception ex)
        {
            TestResult = $"FAILED: {ex.Message}";
        }
        finally
        {
            IsTesting = false;
        }
    }
}
