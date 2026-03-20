using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class StringInterningRisk
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 3: String Interning Risk");

        ConsoleHelpers.PrintNote("The CLR interns string literals into a global table that lives for the entire process.");
        ConsoleHelpers.PrintNote("Interned strings cannot be zeroed, overwritten, or garbage collected.");
        Console.WriteLine();

        // --- .NET string interning ---
        ConsoleHelpers.PrintSubHeader(".NET String Interning Problem");

        ConsoleHelpers.PrintCode("string literal = \"SensitiveApiKey_12345\";");
        string literal = "SensitiveApiKey_12345";

        ConsoleHelpers.PrintCode("string.IsInterned(literal)");
        var interned = string.IsInterned(literal);
        ConsoleHelpers.PrintRisk($"=> {(interned != null ? "\"" + interned + "\"" : "null")}");
        ConsoleHelpers.PrintNote("The literal lives in the intern pool forever — no way to zero or GC it.");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("string runtime = \"Runtime\" + \"Secret\" + DateTime.UtcNow.Ticks;");
        string runtime = "Runtime" + "Secret" + DateTime.UtcNow.Ticks;
        ConsoleHelpers.PrintCode("string.IsInterned(runtime)");
        var runtimeInterned = string.IsInterned(runtime);
        ConsoleHelpers.PrintInfo($"=> {(runtimeInterned != null ? "\"" + runtimeInterned + "\"" : "null")}");
        ConsoleHelpers.PrintNote("Runtime-built strings are not interned, but still cannot be zeroed from managed memory.");
        Console.WriteLine();

        // --- CyString: never interned, disposable ---
        ConsoleHelpers.PrintSubHeader("CyString: Never Interned, Always Disposable");
        ConsoleHelpers.PrintNote("CyString encrypts immediately on construction. The plaintext never exists as a");
        ConsoleHelpers.PrintNote(".NET string, so it's never interned. The buffer is cryptographically zeroed on Dispose().");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("var cyApiKey = new CyString(\"SensitiveApiKey_12345\");");
        var cyApiKey = new CyString("SensitiveApiKey_12345");

        ConsoleHelpers.PrintCode("cyApiKey.ToString()");
        ConsoleHelpers.PrintSecure($"=> {cyApiKey}");
        ConsoleHelpers.PrintNote("Redacted metadata — the plaintext never exists as a .NET string,");
        ConsoleHelpers.PrintNote("so there is nothing for ToString() to return. This is a consequence, not the mechanism.");
        Console.WriteLine();

        // Safe logging
        ConsoleHelpers.PrintSubHeader("Safe Logging with ToString()");
        ConsoleHelpers.PrintCode("Console.WriteLine(cyApiKey);  // safe to pass to loggers");
        ConsoleHelpers.PrintSecure($"=> {cyApiKey}");
        Console.WriteLine();

        // Dispose and verify ObjectDisposedException
        ConsoleHelpers.PrintSubHeader("Memory Zeroing on Dispose");
        ConsoleHelpers.PrintCode("cyApiKey.Dispose();");
        cyApiKey.Dispose();
        ConsoleHelpers.PrintSecure("Memory zeroed.");

        ConsoleHelpers.PrintCode("cyApiKey.ToInsecureString()  // after Dispose");
        try
        {
            _ = cyApiKey.ToInsecureString();
            ConsoleHelpers.PrintRisk("ERROR: Should have thrown ObjectDisposedException!");
        }
        catch (ObjectDisposedException)
        {
            ConsoleHelpers.PrintSecure("=> ObjectDisposedException — access denied after disposal");
        }

        Console.WriteLine();

        // --- Comparison ---
        ConsoleHelpers.PrintSubHeader("Comparison");
        ConsoleHelpers.PrintComparison("Interning", "Literals live forever", "Never interned");
        ConsoleHelpers.PrintComparison("Memory zeroing", "Not possible", "Automatic on Dispose()");
        ConsoleHelpers.PrintComparison("Post-dispose access", "String still readable", "ObjectDisposedException");
        ConsoleHelpers.PrintComparison("Logging safety", "Logs plaintext", "Logs redacted metadata");
    }
}
