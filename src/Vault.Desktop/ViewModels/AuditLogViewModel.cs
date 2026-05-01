using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Vault.Core;
using Vault.Core.Audit;

namespace Vault.Desktop.ViewModels;

public sealed partial class AuditLogViewModel : ViewModelBase
{
    public ObservableCollection<AuditEntryRow> Entries { get; } = [];

    [ObservableProperty]
    private int _totalCount;

    public AuditLogViewModel(VaultSession session)
    {
        var log = session.GetAuditLog();
        TotalCount = log.Count;
        // Show newest first
        foreach (var e in log.OrderByDescending(x => x.Timestamp))
        {
            Entries.Add(new AuditEntryRow(e));
        }
    }

    public event EventHandler? CloseRequested;

    [RelayCommand]
    private void Close() => CloseRequested?.Invoke(this, EventArgs.Empty);
}

public sealed class AuditEntryRow
{
    public DateTimeOffset Timestamp { get; }
    public AuditAction Action { get; }
    public Guid? ItemId { get; }
    public string? Details { get; }

    public AuditEntryRow(AuditEntry e)
    {
        Timestamp = e.Timestamp;
        Action = e.Action;
        ItemId = e.ItemId;
        Details = e.Details;
    }

    public string LocalTime => Timestamp.ToLocalTime().ToString(
        "yyyy-MM-dd HH:mm:ss",
        System.Globalization.CultureInfo.InvariantCulture);

    public string ItemIdShort => ItemId is null ? "" : ItemId.Value.ToString().Substring(0, 8);
}
