using Vault.Crypto;

namespace Vault.Cli;

internal static class ConsolePassword
{
    /// <summary>
    /// Read a password without echoing. Returns SecureBytes (UTF-8 encoded).
    /// On non-interactive stdin (piped), reads a line normally.
    /// </summary>
    public static SecureBytes Read(string prompt)
    {
        Console.Error.Write(prompt);

        if (Console.IsInputRedirected)
        {
            var line = Console.ReadLine() ?? "";
            return SecureBytes.FromUtf8(line);
        }

        var chars = new List<char>(64);
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); break; }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (chars.Count > 0) chars.RemoveAt(chars.Count - 1);
                    continue;
                }
                if (key.KeyChar == 0 || char.IsControl(key.KeyChar)) continue;
                chars.Add(key.KeyChar);
            }

            var s = new string(chars.ToArray());
            try
            {
                return SecureBytes.FromUtf8(s);
            }
            finally
            {
                // String is interned/immutable — can't zero. Best we can do
                // is drop the reference. The char[] we can clear.
            }
        }
        finally
        {
            for (var i = 0; i < chars.Count; i++) chars[i] = '\0';
            chars.Clear();
        }
    }

    public static string ReadConfirmedPassword(string prompt)
    {
        while (true)
        {
            using var first = Read(prompt);
            using var second = Read("Confirm: ");
            if (first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()))
            {
                return System.Text.Encoding.UTF8.GetString(first.AsReadOnlySpan());
            }
            Console.Error.WriteLine("Passwords do not match. Try again.");
        }
    }
}
