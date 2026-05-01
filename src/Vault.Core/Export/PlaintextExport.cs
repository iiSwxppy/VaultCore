using Vault.Core.Items;

namespace Vault.Core.Export;

public sealed record PlaintextItem(
    Guid Id,
    ItemType Type,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    ItemPayload Payload);

public sealed record PlaintextExport(
    int FormatVersion,
    DateTimeOffset ExportedAt,
    List<PlaintextItem> Items);
