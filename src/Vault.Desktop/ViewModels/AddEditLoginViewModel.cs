using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Vault.Core.Items;
using Vault.Crypto;

namespace Vault.Desktop.ViewModels;

/// <summary>
/// Form view model for adding or editing a Login item.
/// Doesn't know about VaultSession — just collects validated form data.
/// Parent decides what to do with the result (add or update).
/// </summary>
public sealed partial class AddEditLoginViewModel : ViewModelBase
{
    public bool IsEdit { get; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveCommand))]
    private string _title = "";

    [ObservableProperty]
    private string _username = "";

    [ObservableProperty]
    private string _password = "";

    [ObservableProperty]
    private bool _passwordRevealed;

    [ObservableProperty]
    private string _url = "";

    [ObservableProperty]
    private string _totpSecret = "";

    [ObservableProperty]
    private string _notes = "";

    [ObservableProperty]
    private int _generatorLength = 24;

    [ObservableProperty]
    private bool _generatorIncludeSymbols = true;

    [ObservableProperty]
    private bool _generatorExcludeAmbiguous;

    [ObservableProperty]
    private string? _validationError;

    /// <summary>The completed payload, set when the user successfully saves.</summary>
    public LoginPayload? Result { get; private set; }

    /// <summary>Called by the View to close the dialog window.</summary>
    public event EventHandler<LoginPayload?>? CloseRequested;

    public AddEditLoginViewModel() : this(null) { }

    public AddEditLoginViewModel(LoginPayload? existing)
    {
        IsEdit = existing is not null;
        if (existing is not null)
        {
            _title = existing.Title;
            _username = existing.Username ?? "";
            _password = existing.Password ?? "";
            _url = existing.Urls.FirstOrDefault() ?? "";
            _totpSecret = existing.TotpSecret ?? "";
            _notes = existing.Notes ?? "";
        }
    }

    [RelayCommand(CanExecute = nameof(CanSave))]
    private void Save()
    {
        // Light validation — most fields are optional for a login.
        if (string.IsNullOrWhiteSpace(Title))
        {
            ValidationError = "Title is required.";
            return;
        }

        // If TOTP supplied, verify it's parseable Base32.
        if (!string.IsNullOrWhiteSpace(TotpSecret))
        {
            try { _ = Base32.Decode(TotpSecret); }
            catch
            {
                ValidationError = "TOTP secret is not valid Base32.";
                return;
            }
        }

        var urls = new List<string>();
        if (!string.IsNullOrWhiteSpace(Url)) urls.Add(Url.Trim());

        Result = new LoginPayload
        {
            Title = Title.Trim(),
            Username = string.IsNullOrWhiteSpace(Username) ? null : Username,
            Password = string.IsNullOrWhiteSpace(Password) ? null : Password,
            Urls = urls,
            TotpSecret = string.IsNullOrWhiteSpace(TotpSecret) ? null : TotpSecret.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant(),
            Notes = string.IsNullOrWhiteSpace(Notes) ? null : Notes,
        };

        CloseRequested?.Invoke(this, Result);
    }

    private bool CanSave() => !string.IsNullOrWhiteSpace(Title);

    [RelayCommand]
    private void Cancel()
    {
        Result = null;
        CloseRequested?.Invoke(this, null);
    }

    [RelayCommand]
    private void GeneratePassword()
    {
        var opts = new PasswordGenerator.CharsetOptions(
            Length: Math.Clamp(GeneratorLength, 4, 128),
            UseLower: true,
            UseUpper: true,
            UseDigits: true,
            UseSymbols: GeneratorIncludeSymbols,
            ExcludeAmbiguous: GeneratorExcludeAmbiguous);
        Password = PasswordGenerator.Charset(opts);
        PasswordRevealed = true;
    }

    [RelayCommand]
    private void TogglePasswordRevealed() => PasswordRevealed = !PasswordRevealed;
}
