using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class TaintTracking
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 4: Taint Tracking - Compromise Propagation");

        ConsoleHelpers.PrintNote("Taint tracking traces which data has been exposed (decrypted) and propagates");
        ConsoleHelpers.PrintNote("that status through derived values. .NET has no built-in equivalent.");
        Console.WriteLine();

        // --- Clean value ---
        ConsoleHelpers.PrintSubHeader("Step 1: Create Clean Values");

        using var a = new CyInt(10);
        using var b = new CyInt(20);

        ConsoleHelpers.PrintCode("var a = new CyInt(10);");
        ConsoleHelpers.PrintCode("var b = new CyInt(20);");
        ConsoleHelpers.PrintCode("a.IsCompromised, a.IsTainted");
        ConsoleHelpers.PrintInfo($"=> IsCompromised: {a.IsCompromised}, IsTainted: {a.IsTainted}");
        ConsoleHelpers.PrintCode("b.IsCompromised, b.IsTainted");
        ConsoleHelpers.PrintInfo($"=> IsCompromised: {b.IsCompromised}, IsTainted: {b.IsTainted}");
        ConsoleHelpers.PrintNote("Freshly created CyTypes are clean: never decrypted, never tainted.");
        Console.WriteLine();

        // --- Compromise via decryption ---
        ConsoleHelpers.PrintSubHeader("Step 2: Decrypt Marks Compromise");

        ConsoleHelpers.PrintCode("int aVal = a.ToInsecureInt();");
        int aVal = a.ToInsecureInt();
        ConsoleHelpers.PrintRisk($"aVal = {aVal}, a.IsCompromised = {a.IsCompromised}");
        ConsoleHelpers.PrintNote("ToInsecureInt() is the only way to get plaintext — it permanently marks the instance.");
        Console.WriteLine();

        // --- Taint propagation ---
        ConsoleHelpers.PrintSubHeader("Step 3: Taint Propagates Through Operations");

        ConsoleHelpers.PrintCode("var c = a + b;  // 'a' is compromised, 'b' is clean");
        using var c = a + b;
        ConsoleHelpers.PrintCode("c.IsTainted");
        ConsoleHelpers.PrintRisk($"=> {c.IsTainted}");
        ConsoleHelpers.PrintNote("Compromised operand 'a' taints the result automatically.");

        ConsoleHelpers.PrintCode("c.IsCompromised");
        ConsoleHelpers.PrintSecure($"=> {c.IsCompromised}");
        ConsoleHelpers.PrintNote("IsTainted = derived from compromised data. IsCompromised = plaintext was extracted.");
        ConsoleHelpers.PrintNote("'c' is tainted but NOT compromised — its value is still encrypted in memory.");
        Console.WriteLine();

        // --- Taint chain ---
        ConsoleHelpers.PrintSubHeader("Step 4: Taint Chain Propagation");

        ConsoleHelpers.PrintCode("var clean = new CyInt(5);");
        ConsoleHelpers.PrintCode("var d = c + clean;  // tainted + clean = tainted");
        using var clean = new CyInt(5);
        using var d = c + clean;
        ConsoleHelpers.PrintCode("d.IsTainted");
        ConsoleHelpers.PrintRisk($"=> {d.IsTainted}");
        ConsoleHelpers.PrintCode("clean.IsTainted");
        ConsoleHelpers.PrintInfo($"=> {clean.IsTainted}");
        ConsoleHelpers.PrintNote("Taint propagates transitively. Clean operands stay clean.");
        Console.WriteLine();

        // --- ClearTaint ---
        ConsoleHelpers.PrintSubHeader("Step 5: Clearing Taint");

        ConsoleHelpers.PrintCode("d.IsTainted");
        ConsoleHelpers.PrintInfo($"=> {d.IsTainted}");

        ConsoleHelpers.PrintCode("d.ClearTaint(\"Reviewed and approved by security team\");");
        d.ClearTaint("Reviewed and approved by security team");
        ConsoleHelpers.PrintCode("d.IsTainted");
        ConsoleHelpers.PrintSecure($"=> {d.IsTainted}");
        ConsoleHelpers.PrintNote("ClearTaint requires a reason string — logged for audit.");
        Console.WriteLine();

        // --- SecurityBreached event ---
        ConsoleHelpers.PrintSubHeader("Step 6: SecurityBreached Event");

        using var monitored = new CyInt(999);

        ConsoleHelpers.PrintCode("var monitored = new CyInt(999);");
        ConsoleHelpers.PrintCode("monitored.SecurityBreached += (sender, evt) => { ... };");
        monitored.SecurityBreached += (sender, evt) =>
        {
            ConsoleHelpers.PrintRisk($"EVENT: SecurityBreached fired! Instance: {evt.InstanceId}");
        };

        ConsoleHelpers.PrintCode("_ = monitored.ToInsecureInt();");
        _ = monitored.ToInsecureInt();
        Console.WriteLine();

        // --- .NET contrast ---
        ConsoleHelpers.PrintSubHeader("Contrast: .NET Has No Taint Tracking");
        ConsoleHelpers.PrintComparison("Taint tracking", "Not available", "Built-in per-instance");
        ConsoleHelpers.PrintComparison("Compromise detection", "Not available", "Automatic on decrypt");
        ConsoleHelpers.PrintComparison("Propagation", "Not available", "Automatic in operations");
        ConsoleHelpers.PrintComparison("Events", "Not available", "SecurityBreached, TaintCleared");
    }
}
