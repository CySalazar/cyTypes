using System.Diagnostics;
using CyTypes.Core.Policy;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class TimingAttacks
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 8: Timing Attack Resistance");

        ConsoleHelpers.PrintNote("Timing attack: attacker measures comparison time to learn where values differ.");
        ConsoleHelpers.PrintNote("string == uses early-exit — stops at first mismatch. Longer time = deeper match.");
        ConsoleHelpers.PrintNote("By trying one character at a time, the attacker reconstructs the secret.");
        Console.WriteLine();

        const int stringLength = 10_000;
        const int iterations = 1_000;

        // Build test strings
        string baseString = new('A', stringLength);
        string matchString = new('A', stringLength);
        string earlyMismatch = "B" + new string('A', stringLength - 1);       // differs at position 0
        string lateMismatch = new string('A', stringLength - 1) + "B";        // differs at position N-1

        // --- Naive string == timing ---
        ConsoleHelpers.PrintSubHeader("Naive string == (early-exit comparison)");

        ConsoleHelpers.PrintCode("string baseStr    = new('A', 10_000);");
        ConsoleHelpers.PrintCode("string earlyMiss  = \"B\" + new string('A', 9_999);  // differs at pos 0");
        ConsoleHelpers.PrintCode("string lateMiss   = new string('A', 9_999) + \"B\";  // differs at pos 9999");
        ConsoleHelpers.PrintCode("// Measure: baseStr == earlyMiss vs baseStr == lateMiss");
        Console.WriteLine();

        var sw = new Stopwatch();

        // Warm up
        for (int i = 0; i < 100; i++)
        {
            _ = baseString == matchString;
            _ = baseString == earlyMismatch;
            _ = baseString == lateMismatch;
        }

        // Measure: early mismatch (pos 0)
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            _ = baseString == earlyMismatch;
        sw.Stop();
        long earlyTicks = sw.ElapsedTicks;

        // Measure: late mismatch (pos N-1)
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            _ = baseString == lateMismatch;
        sw.Stop();
        long lateTicks = sw.ElapsedTicks;

        // Measure: full match
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            _ = baseString == matchString;
        sw.Stop();
        long matchTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintRisk($"Early mismatch (pos 0):     {earlyTicks,8} ticks ({iterations} iterations)");
        ConsoleHelpers.PrintRisk($"Late mismatch  (pos {stringLength - 1}): {lateTicks,8} ticks ({iterations} iterations)");
        ConsoleHelpers.PrintRisk($"Full match:                 {matchTicks,8} ticks ({iterations} iterations)");

        double ratio = lateTicks > 0 ? (double)lateTicks / earlyTicks : 0;
        ConsoleHelpers.PrintRisk($"Late/Early ratio: {ratio:F2}x");
        ConsoleHelpers.PrintNote($"Ratio > 1.0 proves comparison time correlates with match depth — exploitable.");
        Console.WriteLine();

        // --- CyString SecureEquals (constant-time) ---
        ConsoleHelpers.PrintSubHeader("CyString SecureEquals (constant-time via FixedTimeEquals)");

        ConsoleHelpers.PrintCode("var cyBase = new CyString(baseStr, SecurityPolicy.Performance);");
        ConsoleHelpers.PrintCode("var cyEarly = new CyString(earlyMiss, SecurityPolicy.Performance);");
        ConsoleHelpers.PrintCode("var cyLate = new CyString(lateMiss, SecurityPolicy.Performance);");
        ConsoleHelpers.PrintCode("// Measure: cyBase.SecureEquals(cyEarly) vs cyBase.SecureEquals(cyLate)");
        Console.WriteLine();

        // Use Performance policy to allow unlimited decryptions for benchmarking
        using var cyBase = new CyString(baseString, SecurityPolicy.Performance);
        using var cyMatch = new CyString(matchString, SecurityPolicy.Performance);
        using var cyEarlyMismatch = new CyString(earlyMismatch, SecurityPolicy.Performance);
        using var cyLateMismatch = new CyString(lateMismatch, SecurityPolicy.Performance);

        // Warm up
        for (int i = 0; i < 100; i++)
        {
            _ = cyBase.SecureEquals(cyEarlyMismatch);
            _ = cyBase.SecureEquals(cyLateMismatch);
            _ = cyBase.SecureEquals(cyMatch);
        }

        // Measure CyString: early mismatch
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            _ = cyBase.SecureEquals(cyEarlyMismatch);
        sw.Stop();
        long cyEarlyTicks = sw.ElapsedTicks;

        // Measure CyString: late mismatch
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            _ = cyBase.SecureEquals(cyLateMismatch);
        sw.Stop();
        long cyLateTicks = sw.ElapsedTicks;

        // Measure CyString: full match
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            _ = cyBase.SecureEquals(cyMatch);
        sw.Stop();
        long cyMatchTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintSecure($"Early mismatch (pos 0):     {cyEarlyTicks,8} ticks ({iterations} iterations)");
        ConsoleHelpers.PrintSecure($"Late mismatch  (pos {stringLength - 1}): {cyLateTicks,8} ticks ({iterations} iterations)");
        ConsoleHelpers.PrintSecure($"Full match:                 {cyMatchTicks,8} ticks ({iterations} iterations)");

        double cyRatio = cyLateTicks > 0 ? (double)cyLateTicks / cyEarlyTicks : 0;
        ConsoleHelpers.PrintSecure($"Late/Early ratio: {cyRatio:F2}x — near 1.0 = constant time!");
        ConsoleHelpers.PrintNote("HMAC-SHA256 hashes both inputs in full, then FixedTimeEquals compares");
        ConsoleHelpers.PrintNote("the fixed-length digests in constant time. No early-exit possible.");
        Console.WriteLine();

        // --- Summary ---
        ConsoleHelpers.PrintSubHeader("Summary");
        ConsoleHelpers.PrintComparison("Comparison method", "string == (early-exit)", "SecureEquals (FixedTimeEquals)");
        ConsoleHelpers.PrintComparison("Timing leakage", $"Yes ({ratio:F2}x ratio)", $"No ({cyRatio:F2}x ratio)");
        ConsoleHelpers.PrintComparison("Attack surface", "Character-by-character", "None (constant time)");
    }
}
