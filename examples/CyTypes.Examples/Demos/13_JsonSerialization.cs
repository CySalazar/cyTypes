using System.Text.Json;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;
using CyTypes.Primitives.Serialization;

namespace CyTypes.Examples.Demos;

public static class JsonSerialization
{
    // --- Sample DTO with CyType properties ---
    private sealed class SecurePayload
    {
        public CyString? Label { get; set; }
        public CyInt? Score { get; set; }
        public CyDouble? Temperature { get; set; }
    }

    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 13: JSON Serialization - System.Text.Json Integration");

        ConsoleHelpers.PrintNote("CyTypes ships built-in JsonConverters for System.Text.Json.");
        ConsoleHelpers.PrintNote("Serialization DECRYPTS values (calls ToInsecureValue) and marks them compromised.");
        ConsoleHelpers.PrintNote("Deserialization creates fresh encrypted instances with new keys.");
        Console.WriteLine();

        // --- Configure JsonSerializerOptions ---
        ConsoleHelpers.PrintSubHeader("Step 1: Register CyTypes Converters");
        ConsoleHelpers.PrintCode("var options = new JsonSerializerOptions { WriteIndented = true };");
        ConsoleHelpers.PrintCode("options.AddCyTypesConverters();");

        var options = new JsonSerializerOptions { WriteIndented = true };
        options.AddCyTypesConverters();

        ConsoleHelpers.PrintSecure("All 10 CyType converters registered.");
        Console.WriteLine();

        // --- Serialize a CyInt ---
        ConsoleHelpers.PrintSubHeader("Step 2: Serialize Individual CyTypes");

        using var score = new CyInt(42);
        ConsoleHelpers.PrintCode("CyInt score = new CyInt(42);");
        ConsoleHelpers.PrintCode("score.IsCompromised");
        ConsoleHelpers.PrintSecure($"=> {score.IsCompromised}");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("string json = JsonSerializer.Serialize(score, options);");
        string intJson = JsonSerializer.Serialize(score, options);
        ConsoleHelpers.PrintRisk($"json = {intJson}");
        ConsoleHelpers.PrintCode("score.IsCompromised  // after serialization");
        ConsoleHelpers.PrintRisk($"=> {score.IsCompromised}");
        ConsoleHelpers.PrintNote("Serialization called ToInsecureValue() internally, marking the instance compromised.");
        Console.WriteLine();

        // --- Serialize a CyString ---
        using var label = new CyString("secret-token-abc");
        ConsoleHelpers.PrintCode("CyString label = new CyString(\"secret-token-abc\");");
        ConsoleHelpers.PrintCode("string json = JsonSerializer.Serialize(label, options);");
        string strJson = JsonSerializer.Serialize(label, options);
        ConsoleHelpers.PrintRisk($"json = {strJson}");
        ConsoleHelpers.PrintRisk($"label.IsCompromised = {label.IsCompromised}");
        Console.WriteLine();

        // --- Deserialize back ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Step 3: Deserialize Back to CyTypes");

        ConsoleHelpers.PrintCode("CyInt restored = JsonSerializer.Deserialize<CyInt>(\"42\", options);");
        using var restored = JsonSerializer.Deserialize<CyInt>("42", options)!;
        ConsoleHelpers.PrintInfo($"restored (ToString): {restored}");
        ConsoleHelpers.PrintSecure($"restored.IsCompromised = {restored.IsCompromised}");
        ConsoleHelpers.PrintNote("Deserialized instance is freshly encrypted — not compromised.");
        Console.WriteLine();

        // --- Round-trip a DTO ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Step 4: Round-Trip a DTO with CyType Properties");

        ConsoleHelpers.PrintCode("var payload = new SecurePayload");
        ConsoleHelpers.PrintCode("{");
        ConsoleHelpers.PrintCode("    Label = new CyString(\"sensor-01\"),");
        ConsoleHelpers.PrintCode("    Score = new CyInt(95),");
        ConsoleHelpers.PrintCode("    Temperature = new CyDouble(36.6),");
        ConsoleHelpers.PrintCode("};");

        var payload = new SecurePayload
        {
            Label = new CyString("sensor-01"),
            Score = new CyInt(95),
            Temperature = new CyDouble(36.6),
        };

        ConsoleHelpers.PrintCode("string dtoJson = JsonSerializer.Serialize(payload, options);");
        string dtoJson = JsonSerializer.Serialize(payload, options);
        ConsoleHelpers.PrintRisk($"dtoJson =\n{dtoJson}");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("var roundTrip = JsonSerializer.Deserialize<SecurePayload>(dtoJson, options);");
        var roundTrip = JsonSerializer.Deserialize<SecurePayload>(dtoJson, options)!;

        ConsoleHelpers.PrintInfo($"roundTrip.Label (ToString): {roundTrip.Label}");
        ConsoleHelpers.PrintSecure($"roundTrip.Label.IsCompromised = {roundTrip.Label!.IsCompromised}");
        ConsoleHelpers.PrintSecure($"roundTrip.Score.IsCompromised = {roundTrip.Score!.IsCompromised}");
        ConsoleHelpers.PrintNote("Deserialized DTO properties are freshly encrypted in memory.");

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("Key takeaway: serialization is an explicit decryption boundary — use it deliberately.");

        // Cleanup
        payload.Label?.Dispose();
        payload.Score?.Dispose();
        payload.Temperature?.Dispose();
        roundTrip.Label?.Dispose();
        roundTrip.Score?.Dispose();
        roundTrip.Temperature?.Dispose();
    }
}
