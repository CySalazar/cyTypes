using System.Globalization;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class SecurityPolicies
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 5: Security Policies");

        ConsoleHelpers.PrintNote("Policies control HOW data is protected (enclave mode, key rotation, audit level).");
        ConsoleHelpers.PrintNote("Data is ALWAYS encrypted regardless of policy — the policy tunes the trade-off.");
        Console.WriteLine();

        // --- Built-in policies ---
        ConsoleHelpers.PrintSubHeader("Built-in Security Policies");
        ConsoleHelpers.PrintNote("Maximum    — ultra-sensitive data (credentials, PII, cryptographic keys)");
        ConsoleHelpers.PrintNote("Balanced   — sensible default for most applications");
        ConsoleHelpers.PrintNote("Performance — high-throughput scenarios where latency matters most");
        PrintPolicyDetails(SecurityPolicy.Maximum);
        PrintPolicyDetails(SecurityPolicy.Balanced);
        PrintPolicyDetails(SecurityPolicy.Performance);
        Console.WriteLine();

        // --- Creating with different policies ---
        ConsoleHelpers.PrintSubHeader("CyInt with Different Policies");

        ConsoleHelpers.PrintCode("var maxInt  = new CyInt(42, SecurityPolicy.Maximum);");
        ConsoleHelpers.PrintCode("var balInt  = new CyInt(42, SecurityPolicy.Balanced);");
        ConsoleHelpers.PrintCode("var perfInt = new CyInt(42, SecurityPolicy.Performance);");
        using var maxInt = new CyInt(42, SecurityPolicy.Maximum);
        using var balInt = new CyInt(42, SecurityPolicy.Balanced);
        using var perfInt = new CyInt(42, SecurityPolicy.Performance);

        ConsoleHelpers.PrintCode("maxInt.ToString()");
        ConsoleHelpers.PrintInfo($"=> {maxInt}");
        ConsoleHelpers.PrintCode("balInt.ToString()");
        ConsoleHelpers.PrintInfo($"=> {balInt}");
        ConsoleHelpers.PrintCode("perfInt.ToString()");
        ConsoleHelpers.PrintInfo($"=> {perfInt}");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("maxInt.IsCompromised, balInt.IsCompromised, perfInt.IsCompromised");
        ConsoleHelpers.PrintSecure($"=> {maxInt.IsCompromised}, {balInt.IsCompromised}, {perfInt.IsCompromised}");
        ConsoleHelpers.PrintNote("All three are encrypted regardless of policy.");
        Console.WriteLine();

        // --- SecurityPolicyBuilder custom policy ---
        ConsoleHelpers.PrintSubHeader("Custom Policy with SecurityPolicyBuilder");

        ConsoleHelpers.PrintCode("var customPolicy = new SecurityPolicyBuilder()");
        ConsoleHelpers.PrintCode("    .WithName(\"HighSecurityAudit\")");
        ConsoleHelpers.PrintCode("    .WithArithmeticMode(ArithmeticMode.SecureEnclave)");
        ConsoleHelpers.PrintCode("    .WithComparisonMode(ComparisonMode.HmacBased)");
        ConsoleHelpers.PrintCode("    .WithMaxDecryptionCount(50)");
        ConsoleHelpers.PrintCode("    .Build();");
        var customPolicy = new SecurityPolicyBuilder()
            .WithName("HighSecurityAudit")
            .WithArithmeticMode(ArithmeticMode.SecureEnclave)
            .WithComparisonMode(ComparisonMode.HmacBased)
            .WithStringOperationMode(StringOperationMode.SecureEnclave)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(500))
            .WithAuditLevel(AuditLevel.AllOperations)
            .WithTaintMode(TaintMode.Strict)
            .WithMaxDecryptionCount(50)
            .WithAutoDestroy(false)
            .WithAllowDemotion(false)
            .Build();

        ConsoleHelpers.PrintCode("var customInt = new CyInt(42, customPolicy);");
        using var customInt = new CyInt(42, customPolicy);
        ConsoleHelpers.PrintCode("customInt.ToString()");
        ConsoleHelpers.PrintSecure($"=> {customInt}");
        PrintPolicyDetails(customPolicy);
        Console.WriteLine();

        // --- ElevatePolicy ---
        ConsoleHelpers.PrintSubHeader("Policy Elevation");

        ConsoleHelpers.PrintCode("var val = new CyInt(100, SecurityPolicy.Performance);");
        using var val = new CyInt(100, SecurityPolicy.Performance);
        ConsoleHelpers.PrintCode("val.ToString()");
        ConsoleHelpers.PrintInfo($"=> {val}");

        ConsoleHelpers.PrintCode("val.ElevatePolicy(SecurityPolicy.Balanced);");
        val.ElevatePolicy(SecurityPolicy.Balanced);
        ConsoleHelpers.PrintCode("val.ToString()");
        ConsoleHelpers.PrintSecure($"=> {val}");
        ConsoleHelpers.PrintNote("ElevatePolicy upgrades security. Downgrade is blocked unless AllowDemotion=true.");

        ConsoleHelpers.PrintCode("val.ElevatePolicy(SecurityPolicy.Performance);  // downgrade attempt");
        try
        {
            val.ElevatePolicy(SecurityPolicy.Performance);
            ConsoleHelpers.PrintRisk("Should have thrown!");
        }
        catch (Exception ex)
        {
            ConsoleHelpers.PrintSecure($"=> throws {ex.GetType().Name}");
        }
        Console.WriteLine();

        // --- ApplyPolicy with demotion ---
        ConsoleHelpers.PrintSubHeader("ApplyPolicy with Demotion");

        ConsoleHelpers.PrintCode("var demotable = new SecurityPolicyBuilder()");
        ConsoleHelpers.PrintCode("    .WithAllowDemotion(true).Build();");
        var demotable = new SecurityPolicyBuilder()
            .WithName("DemotablePolicy")
            .WithArithmeticMode(ArithmeticMode.SecureEnclave)
            .WithComparisonMode(ComparisonMode.HmacBased)
            .WithStringOperationMode(StringOperationMode.SecureEnclave)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(1000))
            .WithAuditLevel(AuditLevel.DecryptionsAndTransfers)
            .WithTaintMode(TaintMode.Standard)
            .WithMaxDecryptionCount(100)
            .WithAutoDestroy(false)
            .WithAllowDemotion(true)
            .Build();

        ConsoleHelpers.PrintCode("var val2 = new CyInt(200, SecurityPolicy.Balanced);");
        using var val2 = new CyInt(200, SecurityPolicy.Balanced);

        ConsoleHelpers.PrintCode("val2.IsTainted");
        ConsoleHelpers.PrintInfo($"=> {val2.IsTainted}");

        ConsoleHelpers.PrintCode("val2.ApplyPolicy(demotable);");
        val2.ApplyPolicy(demotable);
        ConsoleHelpers.PrintCode("val2.IsTainted");
        ConsoleHelpers.PrintInfo($"=> {val2.IsTainted}");
        ConsoleHelpers.PrintNote("Demotion marks instance as tainted for audit trail.");
    }

    private static void PrintPolicyDetails(SecurityPolicy policy)
    {
        ConsoleHelpers.PrintLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  Policy: {policy.Name}");
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"    Arithmetic:     {policy.Arithmetic}");
        Console.WriteLine($"    Comparison:     {policy.Comparison}");
        Console.WriteLine($"    Memory:         {policy.Memory}");
        Console.WriteLine($"    KeyRotation:    {policy.KeyRotation}");
        Console.WriteLine($"    Audit:          {policy.Audit}");
        Console.WriteLine($"    Taint:          {policy.Taint}");
        Console.WriteLine($"    MaxDecrypt:     {policy.MaxDecryptionCount}");
        Console.WriteLine($"    AutoDestroy:    {policy.AutoDestroy}");
        Console.WriteLine($"    RateLimit:      {policy.DecryptionRateLimit?.ToString(CultureInfo.InvariantCulture) ?? "None"}");
        Console.ResetColor();
    }
}
