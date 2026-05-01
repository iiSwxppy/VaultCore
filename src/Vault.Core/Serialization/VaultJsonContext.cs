using System.Text.Json;
using System.Text.Json.Serialization;
using Vault.Core.Audit;
using Vault.Core.Export;
using Vault.Core.Import;
using Vault.Core.Items;

namespace Vault.Core.Serialization;

[JsonSourceGenerationOptions(
    WriteIndented = false,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ItemPayload))]
[JsonSerializable(typeof(LoginPayload))]
[JsonSerializable(typeof(SecureNotePayload))]
[JsonSerializable(typeof(CreditCardPayload))]
[JsonSerializable(typeof(IdentityPayload))]
[JsonSerializable(typeof(SshKeyPayload))]
[JsonSerializable(typeof(TotpSeedPayload))]
[JsonSerializable(typeof(VaultManifest))]
[JsonSerializable(typeof(BitwardenExport))]
[JsonSerializable(typeof(AuditEntry))]
public partial class VaultJsonContext : JsonSerializerContext { }

[JsonSourceGenerationOptions(
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(PlaintextExport))]
[JsonSerializable(typeof(PlaintextItem))]
[JsonSerializable(typeof(ItemPayload))]
[JsonSerializable(typeof(LoginPayload))]
[JsonSerializable(typeof(SecureNotePayload))]
[JsonSerializable(typeof(CreditCardPayload))]
[JsonSerializable(typeof(IdentityPayload))]
[JsonSerializable(typeof(SshKeyPayload))]
[JsonSerializable(typeof(TotpSeedPayload))]
public partial class PlaintextExportJsonContext : JsonSerializerContext { }
