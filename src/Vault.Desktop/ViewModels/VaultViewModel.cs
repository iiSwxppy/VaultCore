using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Vault.Core;
using Vault.Core.Items;
using Vault.Crypto;
using Vault.Desktop.Services;

namespace Vault.Desktop.ViewModels;

public sealed partial class VaultViewModel : ViewModelBase, IDisposable
{
    private readonly SessionService _sessionService;
    private readonly ClipboardService _clipboard;
    private readonly Action _onLock;

    [ObservableProperty]
    private string _searchQuery = "";

    [ObservableProperty]
    private ItemRowViewModel? _selectedItem;

    [ObservableProperty]
    private ItemDetailViewModel? _detail;

    [ObservableProperty]
    private string? _statusMessage;

    public ObservableCollection<ItemRowViewModel> Items { get; } = [];

    /// <summary>
    /// Raised when the VM wants the View to open the Add/Edit dialog.
    /// View handler: open window, await result, then call HandleAddResult / HandleEditResult.
    /// </summary>
    public event EventHandler<AddEditRequest>? AddEditRequested;

    public event EventHandler<ConfirmRequest>? ConfirmRequested;
    public event EventHandler? AuditLogRequested;
    public event EventHandler? SettingsRequested;
    public event EventHandler<SyncRequest>? SyncRequested;
    public event EventHandler? ConfigureSyncRequested;

    public VaultViewModel(SessionService sessionService, ClipboardService clipboard, Action onLock)
    {
        _sessionService = sessionService;
        _clipboard = clipboard;
        _onLock = onLock;

        LoadItems();
    }

    partial void OnSearchQueryChanged(string value) => LoadItems();

    partial void OnSelectedItemChanged(ItemRowViewModel? value)
    {
        Detail?.Dispose();
        Detail = null;
        if (value is null || _sessionService.Current is null) return;

        var session = _sessionService.Current;
        try
        {
            var payload = session.DecryptItem(value.Id, logAccess: true);
            Detail = new ItemDetailViewModel(payload, _clipboard, MarkStatus);
        }
        catch (Exception ex)
        {
            MarkStatus($"Could not decrypt item: {ex.Message}");
        }
    }

    private void LoadItems()
    {
        Items.Clear();
        var session = _sessionService.Current;
        if (session is null) return;

        var q = SearchQuery?.Trim();
        var rows = session.Items
            .Select(i =>
            {
                ItemPayload? payload;
                try { payload = session.DecryptItem(i.Id); }
                catch { return null; }
                return new ItemRowViewModel(
                    i.Id,
                    payload.Title,
                    i.Type,
                    payload is LoginPayload l ? l.Username : null,
                    payload is LoginPayload login ? login.Urls.FirstOrDefault() : null,
                    i.UpdatedAt);
            })
            .Where(r => r is not null)
            .Cast<ItemRowViewModel>()
            .Where(r => string.IsNullOrEmpty(q) || r.Matches(q))
            .OrderBy(r => r.Title, StringComparer.OrdinalIgnoreCase);

        foreach (var row in rows) Items.Add(row);
    }

    [RelayCommand]
    private void Lock()
    {
        SelectedItem = null;
        Detail?.Dispose();
        Detail = null;
        _onLock();
    }

    [RelayCommand]
    private void Refresh() => LoadItems();

    [RelayCommand]
    private void AddLogin()
    {
        AddEditRequested?.Invoke(this, new AddEditRequest(Existing: null, OnSave: HandleAddResult));
    }

    [RelayCommand]
    private void EditSelected()
    {
        if (SelectedItem is null || _sessionService.Current is null) return;
        var item = _sessionService.Current.Items.FirstOrDefault(i => i.Id == SelectedItem.Id);
        if (item is null || item.Type != ItemType.Login) return;

        try
        {
            var payload = (LoginPayload)_sessionService.Current.DecryptItem(item.Id);
            var id = item.Id;
            AddEditRequested?.Invoke(this, new AddEditRequest(
                Existing: payload,
                OnSave: result => HandleEditResult(id, result)));
        }
        catch (Exception ex)
        {
            MarkStatus($"Could not load item for edit: {ex.Message}");
        }
    }

    [RelayCommand]
    private void DeleteSelected()
    {
        if (SelectedItem is null) return;
        var id = SelectedItem.Id;
        var title = SelectedItem.Title;

        ConfirmRequested?.Invoke(this, new ConfirmRequest(
            Title: "Delete item",
            Message: $"Delete '{title}'? This cannot be undone.",
            ConfirmLabel: "Delete",
            IsDestructive: true,
            OnResult: confirmed =>
            {
                if (!confirmed) return;
                if (_sessionService.Current is null) return;
                _sessionService.Current.DeleteItem(id);
                SelectedItem = null;
                Detail?.Dispose();
                Detail = null;
                LoadItems();
                MarkStatus($"Deleted '{title}'.");
            }));
    }

    [RelayCommand]
    private void ShowAuditLog() => AuditLogRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void ShowSettings() => SettingsRequested?.Invoke(this, EventArgs.Empty);

    [RelayCommand]
    private void Sync()
    {
        SyncRequested?.Invoke(this, new SyncRequest(MarkStatus));
    }

    [RelayCommand]
    private void ConfigureSync()
    {
        ConfigureSyncRequested?.Invoke(this, EventArgs.Empty);
    }

    private void HandleAddResult(LoginPayload? payload)
    {
        if (payload is null || _sessionService.Current is null) return;
        var newId = _sessionService.Current.AddItem(payload);
        LoadItems();
        SelectedItem = Items.FirstOrDefault(r => r.Id == newId);
        MarkStatus($"Added '{payload.Title}'.");
    }

    private void HandleEditResult(Guid id, LoginPayload? payload)
    {
        if (payload is null || _sessionService.Current is null) return;
        _sessionService.Current.UpdateItem(id, payload);
        LoadItems();
        SelectedItem = Items.FirstOrDefault(r => r.Id == id);
        // Refresh detail panel with the new content.
        OnSelectedItemChanged(SelectedItem);
        MarkStatus($"Updated '{payload.Title}'.");
    }

    private void MarkStatus(string message)
    {
        StatusMessage = message;
    }

    public void Dispose()
    {
        Detail?.Dispose();
        Detail = null;
    }
}

public sealed record AddEditRequest(LoginPayload? Existing, Action<LoginPayload?> OnSave);

public sealed record ConfirmRequest(
    string Title,
    string Message,
    string ConfirmLabel,
    bool IsDestructive,
    Action<bool> OnResult);

public sealed record SyncRequest(Action<string> SetStatus);

public sealed class ItemRowViewModel(
    Guid id, string title, ItemType type, string? username, string? primaryUrl, DateTimeOffset updatedAt) : ViewModelBase
{
    public Guid Id { get; } = id;
    public string Title { get; } = title;
    public ItemType Type { get; } = type;
    public string? Username { get; } = username;
    public string? PrimaryUrl { get; } = primaryUrl;
    public DateTimeOffset UpdatedAt { get; } = updatedAt;

    public string Subtitle => Type switch
    {
        ItemType.Login => string.IsNullOrEmpty(Username) ? (PrimaryUrl ?? "") : Username,
        _ => Type.ToString(),
    };

    public bool Matches(string query)
    {
        return Title.Contains(query, StringComparison.OrdinalIgnoreCase)
            || (Username?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
            || (PrimaryUrl?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false);
    }
}

public sealed partial class ItemDetailViewModel : ViewModelBase, IDisposable
{
    private readonly ItemPayload _payload;
    private readonly ClipboardService _clipboard;
    private readonly Action<string> _setStatus;
    private readonly byte[]? _totpSecretBytes;
    private DispatcherTimer? _totpTimer;
    private bool _disposed;

    public ItemDetailViewModel(ItemPayload payload, ClipboardService clipboard, Action<string> setStatus)
    {
        _payload = payload;
        _clipboard = clipboard;
        _setStatus = setStatus;

        if (_payload is LoginPayload login && !string.IsNullOrEmpty(login.TotpSecret))
        {
            try
            {
                _totpSecretBytes = Base32.Decode(login.TotpSecret);
                RefreshTotp();
                StartTotpTimer();
            }
            catch { /* malformed secret — leave totp off */ }
        }
    }

    public string Title => _payload.Title;
    public string TypeName => _payload.GetType().Name.Replace("Payload", "", StringComparison.Ordinal);
    public string? Notes => _payload.Notes;

    public string? Username => (_payload as LoginPayload)?.Username;
    public string? Password => (_payload as LoginPayload)?.Password;
    public IReadOnlyList<string> Urls => (_payload as LoginPayload)?.Urls ?? (IReadOnlyList<string>)[];

    public bool IsLogin => _payload is LoginPayload;
    public bool HasTotp => _totpSecretBytes is not null;
    public bool HasUrls => Urls.Count > 0;
    public bool HasNotes => !string.IsNullOrEmpty(Notes);

    [ObservableProperty]
    private string? _currentTotp;

    [ObservableProperty]
    private int _totpRemainingSeconds;

    private void StartTotpTimer()
    {
        _totpTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _totpTimer.Tick += (_, _) => RefreshTotp();
        _totpTimer.Start();
    }

    private void RefreshTotp()
    {
        if (_totpSecretBytes is null) return;
        var now = DateTimeOffset.UtcNow;
        CurrentTotp = Totp.Generate(_totpSecretBytes, now);
        TotpRemainingSeconds = Totp.SecondsUntilNext(now);
    }

    [RelayCommand]
    private async Task CopyUsername()
    {
        if (Username is null) return;
        await _clipboard.CopyAsync(Username).ConfigureAwait(false);
        _setStatus("Username copied. Will clear from clipboard in 30s.");
    }

    [RelayCommand]
    private async Task CopyPassword()
    {
        if (Password is null) return;
        await _clipboard.CopyAsync(Password).ConfigureAwait(false);
        _setStatus("Password copied. Will clear from clipboard in 30s.");
    }

    [RelayCommand]
    private async Task CopyTotp()
    {
        if (CurrentTotp is null) return;
        await _clipboard.CopyAsync(CurrentTotp).ConfigureAwait(false);
        _setStatus($"TOTP code copied ({TotpRemainingSeconds}s remaining).");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _totpTimer?.Stop();
        _totpTimer = null;
        if (_totpSecretBytes is not null)
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_totpSecretBytes);
        _disposed = true;
    }
}
