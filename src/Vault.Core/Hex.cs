namespace Vault.Core;

internal static class Hex
{
    public static string ToHex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
    public static byte[] FromHex(string hex) => Convert.FromHexString(hex);
}
