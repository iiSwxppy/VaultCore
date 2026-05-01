using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Vault.Core;
using Vault.Crypto;
using Vault.Desktop.Services;

namespace Vault.Desktop.ViewModels;

public sealed partial class UnlockViewModel : ViewModelBase
{
    private readonly AppSettings _settings;
    private readonly SessionService _sessionService;
    private readonly FailedAttemptLog _failedAttempts;

    /// <summary>
    /// Raised after a successful unlock, BEFORE credentials are cleared.
    /// Lets the shell hand them off to the background sync service if enabled.
    /// Listeners must consume the bytes synchronously — they're zeroed right after.
    /// </summary>
    public event EventHandler<UnlockedEventArgs>? Unlocked;

    [ObservableProperty]
    private string _vaultPath;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(UnlockCommand))]
    [NotifyCanExecuteChangedFor(nameof(CreateVaultCommand))]
    private string _password = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(UnlockCommand))]
    [NotifyCanExecuteChangedFor(nameof(CreateVaultCommand))]
    private string _secretKey = "";

    [ObservableProperty]
    private string? _statusMessage;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _isLockedOut;

    [ObservableProperty]
    private string? _lockoutMessage;

    [ObservableProperty]
    private string? _newSecretKeyToShow;

    public UnlockViewModel(AppSettings settings, SessionService sessionService, FailedAttemptLog failedAttempts)
    {
        _settings = settings;
        _sessionService = sessionService;
        _failedAttempts = failedAttempts;
        _vaultPath = settings.LastVaultPath ?? "";

        UpdateLockoutStatus();
    }

    public bool VaultExists => !string.IsNullOrEmpty(VaultPath) && File.Exists(VaultPath);

    partial void OnVaultPathChanged(string value)
    {
        OnPropertyChanged(nameof(VaultExists));
        UnlockCommand.NotifyCanExecuteChanged();
        CreateVaultCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanUnlock))]
    private async Task Unlock()
    {
        UpdateLockoutStatus();
        if (IsLockedOut) return;

        IsBusy = true;
        StatusMessage = "Deriving keys (Argon2id, this takes ~1 second)...";
        try
        {
            var pwdBytes = System.Text.Encoding.UTF8.GetBytes(Password);
            VaultSession session;
            try
            {
                session = await Task.Run(() => VaultSession.Unlock(VaultPath, pwdBytes, SecretKey)).ConfigureAwait(true);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(pwdBytes);
            }

            _failedAttempts.Reset();
            _settings.LastVaultPath = VaultPath;
            _settings.Save();

            // Hand off ownership.
            _sessionService.Set(session);

            // Emit the unlocked event with credentials so the shell can
            // optionally enable background sync. Listeners run synchronously
            // before we zero the bytes below.
            try
            {
                var pwdCopy = System.Text.Encoding.UTF8.GetBytes(Password);
                try
                {
                    Unlocked?.Invoke(this, new UnlockedEventArgs(VaultPath, pwdCopy, SecretKey));
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(pwdCopy);
                }
            }
            catch { /* listener errors must not break unlock */ }

            ClearSensitive();
        }
        catch (InvalidPasswordException)
        {
            _failedAttempts.RecordFailure();
            StatusMessage = "Incorrect master password or secret key.";
            UpdateLockoutStatus();
        }
        catch (FileNotFoundException)
        {
            StatusMessage = "Vault file not found.";
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            StatusMessage = $"Vault is corrupted or tampered: {ex.Message}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Unlock failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanUnlock() => !IsBusy && !IsLockedOut && VaultExists
        && !string.IsNullOrEmpty(Password) && !string.IsNullOrEmpty(SecretKey);

    [RelayCommand(CanExecute = nameof(CanCreateVault))]
    private async Task CreateVault()
    {
        if (string.IsNullOrEmpty(VaultPath)) return;
        if (File.Exists(VaultPath))
        {
            StatusMessage = "A file already exists at this path.";
            return;
        }

        IsBusy = true;
        StatusMessage = "Generating Secret Key and creating vault (Argon2id ~1s)...";
        try
        {
            var sk = Vault.Crypto.SecretKey.Generate();
            var pwdBytes = System.Text.Encoding.UTF8.GetBytes(Password);
            try
            {
                using var session = await Task.Run(() => VaultSession.Create(VaultPath, pwdBytes, sk)).ConfigureAwait(true);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(pwdBytes);
            }

            // Show the secret key to the user. They MUST write it down.
            NewSecretKeyToShow = sk;
            SecretKey = sk; // pre-fill so they can immediately unlock with the same value
            StatusMessage = "Vault created. WRITE DOWN the Secret Key below.";
            _settings.LastVaultPath = VaultPath;
            _settings.Save();
            OnPropertyChanged(nameof(VaultExists));
            UnlockCommand.NotifyCanExecuteChanged();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not create vault: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanCreateVault() => !IsBusy && !string.IsNullOrEmpty(VaultPath)
        && !File.Exists(VaultPath) && !string.IsNullOrEmpty(Password);

    [RelayCommand]
    private void DismissNewSecretKey()
    {
        NewSecretKeyToShow = null;
    }

    private void UpdateLockoutStatus()
    {
        var until = _failedAttempts.LockoutUntil();
        IsLockedOut = until.HasValue;
        if (until.HasValue)
        {
            var remaining = until.Value - DateTimeOffset.UtcNow;
            LockoutMessage = $"Too many failed attempts. Locked out for {remaining.TotalSeconds:F0}s.";
            UnlockCommand.NotifyCanExecuteChanged();
        }
        else
        {
            LockoutMessage = null;
        }
    }

    private void ClearSensitive()
    {
        Password = "";
        SecretKey = "";
    }
}

/// <summary>
/// Payload of the <see cref="UnlockViewModel.Unlocked"/> event. The byte
/// buffer is owned by the emitter and zeroed immediately after listeners
/// return — listeners must NOT capture the reference.
/// </summary>
public sealed class UnlockedEventArgs(string vaultPath, byte[] masterPassword, string secretKey) : EventArgs
{
    public string VaultPath { get; } = vaultPath;
    public byte[] MasterPassword { get; } = masterPassword;
    public string SecretKey { get; } = secretKey;
}
