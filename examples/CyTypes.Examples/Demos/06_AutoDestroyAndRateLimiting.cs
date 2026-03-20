using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Core.Security;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class AutoDestroyAndRateLimiting
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 6: Auto-Destroy and Rate Limiting");

        ConsoleHelpers.PrintNote("Use cases: one-time passwords (OTP), temporary auth tokens, session secrets,");
        ConsoleHelpers.PrintNote("or any value that should self-destruct after a limited number of reads.");
        Console.WriteLine();

        // --- Auto-Destroy after MaxDecryptionCount ---
        ConsoleHelpers.PrintSubHeader("Auto-Destroy: MaxDecryptionCount = 3");

        ConsoleHelpers.PrintCode("var policy = new SecurityPolicyBuilder()");
        ConsoleHelpers.PrintCode("    .WithMaxDecryptionCount(3)");
        ConsoleHelpers.PrintCode("    .WithAutoDestroy(true)");
        ConsoleHelpers.PrintCode("    .Build();");
        var autoDestroyPolicy = new SecurityPolicyBuilder()
            .WithName("AutoDestroyDemo")
            .WithArithmeticMode(ArithmeticMode.SecureEnclave)
            .WithComparisonMode(ComparisonMode.HmacBased)
            .WithStringOperationMode(StringOperationMode.SecureEnclave)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(1000))
            .WithAuditLevel(AuditLevel.AllOperations)
            .WithTaintMode(TaintMode.Standard)
            .WithMaxDecryptionCount(3)
            .WithAutoDestroy(true)
            .WithAllowDemotion(false)
            .Build();

        ConsoleHelpers.PrintCode("var limited = new CyInt(42, policy);");
        var limited = new CyInt(42, autoDestroyPolicy);
        ConsoleHelpers.PrintNote("SecurityContext tracks the decryption counter. On limit reached + AutoDestroy=true,");
        ConsoleHelpers.PrintNote("Dispose() fires automatically — CryptographicOperations.ZeroMemory wipes the buffer.");
        Console.WriteLine();

        for (int i = 1; i <= 4; i++)
        {
            ConsoleHelpers.PrintCode($"limited.ToInsecureInt()  // attempt #{i}");
            try
            {
                int val = limited.ToInsecureInt();
                ConsoleHelpers.PrintInfo($"=> {val} (IsDisposed: {limited.IsDisposed})");
            }
            catch (ObjectDisposedException)
            {
                ConsoleHelpers.PrintSecure($"=> ObjectDisposedException — auto-destroyed after limit!");
                break;
            }
        }

        Console.WriteLine();
        ConsoleHelpers.PrintSecure("After auto-destroy: permanently disposed, memory zeroed, no recovery.");
        Console.WriteLine();

        // --- Rate Limiting ---
        ConsoleHelpers.PrintSubHeader("Rate Limiting: DecryptionRateLimit = 5/sec");

        ConsoleHelpers.PrintCode("var policy = new SecurityPolicyBuilder()");
        ConsoleHelpers.PrintCode("    .WithDecryptionRateLimit(5)");
        ConsoleHelpers.PrintCode("    .Build();");
        ConsoleHelpers.PrintNote("Caps decryptions/sec to throttle automated extraction attacks.");
        var rateLimitPolicy = new SecurityPolicyBuilder()
            .WithName("RateLimitDemo")
            .WithArithmeticMode(ArithmeticMode.SecureEnclave)
            .WithComparisonMode(ComparisonMode.HmacBased)
            .WithStringOperationMode(StringOperationMode.SecureEnclave)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(1000))
            .WithAuditLevel(AuditLevel.DecryptionsAndTransfers)
            .WithTaintMode(TaintMode.Standard)
            .WithMaxDecryptionCount(1000)
            .WithAutoDestroy(false)
            .WithAllowDemotion(false)
            .WithDecryptionRateLimit(5)
            .Build();

        ConsoleHelpers.PrintCode("var rateLimited = new CyInt(100, policy);");
        using var rateLimited = new CyInt(100, rateLimitPolicy);
        int succeeded = 0;
        bool rateLimitHit = false;

        ConsoleHelpers.PrintCode("for (int i = 0; i < 20; i++) rateLimited.ToInsecureInt();");
        ConsoleHelpers.PrintInfo("Attempting rapid decryptions in a tight loop...");

        for (int i = 0; i < 20; i++)
        {
            try
            {
                _ = rateLimited.ToInsecureInt();
                succeeded++;
            }
            catch (RateLimitExceededException ex)
            {
                ConsoleHelpers.PrintSecure($"RateLimitExceededException after {succeeded} decryptions: {ex.Message}");
                rateLimitHit = true;
                break;
            }
        }

        if (!rateLimitHit)
        {
            ConsoleHelpers.PrintInfo($"All {succeeded} decryptions succeeded (burst completed within window).");
        }

        Console.WriteLine();

        // --- .NET contrast ---
        ConsoleHelpers.PrintSubHeader("Contrast: .NET Has No Access Controls");
        ConsoleHelpers.PrintComparison("Decryption limit", "Unlimited reads", "Configurable MaxDecryptionCount");
        ConsoleHelpers.PrintComparison("Auto-destroy", "Never", "After limit reached");
        ConsoleHelpers.PrintComparison("Rate limiting", "Not available", "Decryptions/sec cap");
        ConsoleHelpers.PrintComparison("Use case", "N/A", "One-time tokens, OTPs, temp secrets");
    }
}
