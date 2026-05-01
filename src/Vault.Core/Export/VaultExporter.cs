using System.Text.Json;
using Vault.Core.Items;
using Vault.Core.Serialization;

namespace Vault.Core.Export;

/// <summary>
/// Plaintext JSON export (DANGEROUS, only after explicit double confirmation).
/// Encrypted backup export = just copy the .vault file (it's already AEAD+HMAC protected).
/// </summary>
public static class VaultExporter
{
    /// <summary>
    /// Write all items to a plaintext JSON file. Caller is responsible for confirming
    /// the user really wants this — the result is a complete vault dump in cleartext.
    /// </summary>
    public static void ExportPlaintextJson(VaultSession session, string outputPath)
    {
        var items = session.Items
            .OrderBy(i => i.CreatedAt)
            .Select(i => new PlaintextItem(
                i.Id,
                i.Type,
                i.CreatedAt,
                i.UpdatedAt,
                session.DecryptItem(i.Id)))
            .ToList();

        var export = new PlaintextExport(
            FormatVersion: 1,
            ExportedAt: DateTimeOffset.UtcNow,
            Items: items);

        var json = JsonSerializer.Serialize(export, PlaintextExportJsonContext.Default.PlaintextExport);

        var tmp = outputPath + ".tmp";
        File.WriteAllText(tmp, json);
        TrySetUserOnly(tmp);
        if (File.Exists(outputPath)) File.Replace(tmp, outputPath, null);
        else File.Move(tmp, outputPath);
    }

    /// <summary>
    /// Encrypted backup = copy the .vault file. The file format is already
    /// AEAD-protected per item + HMAC over the whole body, so a copy is a
    /// complete encrypted backup. Restore = open with same password+SecretKey.
    /// </summary>
    public static void ExportEncryptedBackup(string vaultPath, string outputPath)
    {
        File.Copy(vaultPath, outputPath, overwrite: true);
        TrySetUserOnly(outputPath);
    }

    private static void TrySetUserOnly(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { /* best effort */ }
        }
        // On Windows, NTFS ACLs by default inherit user-only for files in user profile.
    }
}
