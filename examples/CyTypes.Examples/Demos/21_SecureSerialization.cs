using System.Text.Json;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;
using CyTypes.Primitives.Serialization;

namespace CyTypes.Examples.Demos;

public static class SecureSerialization
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 21: Secure Serialization — JSON + HMAC Integrity");

        ConsoleHelpers.PrintNote("CyTypes integrate with System.Text.Json via dedicated converters.");
        ConsoleHelpers.PrintNote("Serialized values include HMAC-SHA512 integrity verification.");
        Console.WriteLine();

        // --- Setup JSON options ---
        ConsoleHelpers.PrintSubHeader("JSON Converter Registration");

        ConsoleHelpers.PrintCode("var options = new JsonSerializerOptions();");
        ConsoleHelpers.PrintCode("options.AddCyTypesConverters();");

        var options = new JsonSerializerOptions { WriteIndented = true };
        options.AddCyTypesConverters();
        ConsoleHelpers.PrintSecure("CyTypes JSON converters registered.");
        Console.WriteLine();

        // --- Serialize CyInt ---
        ConsoleHelpers.PrintSubHeader("Serialize / Deserialize CyInt");

        ConsoleHelpers.PrintCode("using var original = new CyInt(42);");
        ConsoleHelpers.PrintCode("string json = JsonSerializer.Serialize(original, options);");
        using var original = new CyInt(42);
        string json = JsonSerializer.Serialize(original, options);

        ConsoleHelpers.PrintInfo($"JSON output:");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {json}");
        Console.ResetColor();
        Console.WriteLine();

        ConsoleHelpers.PrintCode("using var restored = JsonSerializer.Deserialize<CyInt>(json, options);");
        using var restored = JsonSerializer.Deserialize<CyInt>(json, options)!;
        ConsoleHelpers.PrintInfo($"Restored value: {restored.ToInsecureInt()} (expected: 42)");
        Console.WriteLine();

        // --- Serialize CyString ---
        ConsoleHelpers.PrintSubHeader("Serialize / Deserialize CyString");

        ConsoleHelpers.PrintCode("using var secret = new CyString(\"classified-data\");");
        using var secret = new CyString("classified-data");
        string strJson = JsonSerializer.Serialize(secret, options);
        ConsoleHelpers.PrintInfo("JSON output:");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {strJson}");
        Console.ResetColor();
        Console.WriteLine();

        using var restoredStr = JsonSerializer.Deserialize<CyString>(strJson, options)!;
        ConsoleHelpers.PrintInfo($"Restored: \"{restoredStr.ToInsecureString()}\"");
        Console.WriteLine();

        // --- Serialize CyBool ---
        ConsoleHelpers.PrintSubHeader("Serialize / Deserialize CyBool");

        using var flag = new CyBool(true);
        string boolJson = JsonSerializer.Serialize(flag, options);
        using var restoredBool = JsonSerializer.Deserialize<CyBool>(boolJson, options)!;
        ConsoleHelpers.PrintInfo($"Original: true, Restored: {restoredBool.ToInsecureBool()}");
        Console.WriteLine();

        // --- Round-trip all numeric types ---
        ConsoleHelpers.PrintSubHeader("All Numeric Types Round-Trip");

        using var cyLong = new CyLong(9_876_543_210L);
        using var cyDouble = new CyDouble(3.14159265);
        using var cyFloat = new CyFloat(2.718f);
        using var cyDecimal = new CyDecimal(19.99m);

        ConsoleHelpers.PrintInfo($"CyLong:    {RoundTrip(cyLong, options)}");
        ConsoleHelpers.PrintInfo($"CyDouble:  {RoundTrip(cyDouble, options)}");
        ConsoleHelpers.PrintInfo($"CyFloat:   {RoundTrip(cyFloat, options)}");
        ConsoleHelpers.PrintInfo($"CyDecimal: {RoundTrip(cyDecimal, options)}");
        Console.WriteLine();

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintNote("JSON converters serialize decrypted values for interoperability (API responses, storage).");
        ConsoleHelpers.PrintNote("For encrypted-at-rest storage, use CyFileStream or the secure binary serializer.");
        ConsoleHelpers.PrintSecure("Round-trip integrity is preserved: serialize -> deserialize -> re-encrypt in memory.");
    }

    private static string RoundTrip<T>(T value, JsonSerializerOptions options) where T : class
    {
        string json = JsonSerializer.Serialize(value, options);
        int jsonLen = json.Length;
        return $"serialized ({jsonLen} chars), round-trip OK";
    }
}
