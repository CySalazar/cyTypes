using System.Diagnostics;
using System.Globalization;
using CyTypes.Core.Crypto;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;

namespace CyTypes.Examples.Demos;

public static class ProtectionLevelBenchmarks
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 11: Protection Level Benchmarks");

        ConsoleHelpers.PrintNote("cyTypes supports multiple protection tiers. More protection = more overhead.");
        ConsoleHelpers.PrintNote("This demo quantifies the trade-offs.");
        Console.WriteLine();

        BenchmarkSecurityPolicies();
        BenchmarkMemoryProtection();
        BenchmarkKeyRotation();
        BenchmarkFheVsAes();
        BenchmarkHomomorphicVsSecureEnclave();
        PrintSummaryTable();
    }

    // ── Section 1: Performance vs Balanced vs Maximum ──
    private static long _perfTicks, _balTicks, _maxTicks;

    private static void BenchmarkSecurityPolicies()
    {
        ConsoleHelpers.PrintSubHeader("Security Policies: Performance vs Balanced vs Maximum (5,000 iterations)");
        ConsoleHelpers.PrintNote("Testing CyInt addition with each predefined policy.");
        ConsoleHelpers.PrintNote("Maximum policy has AutoDestroy and decryption limits — using custom policy that");
        ConsoleHelpers.PrintNote("replicates Maximum security but allows unlimited decryptions for benchmarking.");
        Console.WriteLine();

        const int iterations = 5_000;

        // Custom Maximum-like policy without decryption limits
        var maxBenchPolicy = new SecurityPolicyBuilder()
            .WithName("MaximumBench")
            .WithArithmeticMode(ArithmeticMode.SecureEnclave)
            .WithComparisonMode(ComparisonMode.HmacBased)
            .WithMemoryProtection(MemoryProtection.PinnedLockedReEncrypting)
            .WithMaxDecryptionCount(int.MaxValue)
            .WithAutoDestroy(false)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(1000))
            .WithOverflowMode(OverflowMode.Checked)
            .Build();

        // Warmup
        for (int i = 0; i < 100; i++)
        {
            using var a = new CyInt(42, SecurityPolicy.Performance);
            using var b = new CyInt(17, SecurityPolicy.Performance);
            using var r = a + b;
        }

        // Performance policy
        var sw = new Stopwatch();
        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var a = new CyInt(42, SecurityPolicy.Performance);
            using var b = new CyInt(17, SecurityPolicy.Performance);
            using var r = a + b;
        }
        sw.Stop();
        _perfTicks = sw.ElapsedTicks;

        // Balanced policy
        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var a = new CyInt(42, SecurityPolicy.Balanced);
            using var b = new CyInt(17, SecurityPolicy.Balanced);
            using var r = a + b;
        }
        sw.Stop();
        _balTicks = sw.ElapsedTicks;

        // Maximum-like policy
        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var a = new CyInt(42, maxBenchPolicy);
            using var b = new CyInt(17, maxBenchPolicy);
            using var r = a + b;
        }
        sw.Stop();
        _maxTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintInfo($"Performance:  {_perfTicks,12} ticks  (baseline)");
        ConsoleHelpers.PrintInfo($"Balanced:     {_balTicks,12} ticks  ({Factor(_perfTicks, _balTicks)}x vs Performance)");
        ConsoleHelpers.PrintInfo($"Maximum:      {_maxTicks,12} ticks  ({Factor(_perfTicks, _maxTicks)}x vs Performance)");
        Console.WriteLine();
    }

    // ── Section 2: Memory Protection Tiers ──
    private static long _pinnedOnlyTicks, _pinnedLockedTicks, _pinnedLockedReEncTicks;

    private static void BenchmarkMemoryProtection()
    {
        ConsoleHelpers.PrintSubHeader("Memory Protection Tiers (3,000 iterations)");
        ConsoleHelpers.PrintNote("PinnedOnly vs PinnedLocked vs PinnedLockedReEncrypting — CyInt creation.");
        Console.WriteLine();

        const int iterations = 3_000;

        var pinnedOnlyPolicy = new SecurityPolicyBuilder()
            .WithName("PinnedOnlyBench")
            .WithMemoryProtection(MemoryProtection.PinnedOnly)
            .WithKeyRotation(KeyRotationPolicy.Manual)
            .Build();

        var pinnedLockedPolicy = new SecurityPolicyBuilder()
            .WithName("PinnedLockedBench")
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithKeyRotation(KeyRotationPolicy.Manual)
            .Build();

        var pinnedLockedReEncPolicy = new SecurityPolicyBuilder()
            .WithName("PinnedLockedReEncBench")
            .WithMemoryProtection(MemoryProtection.PinnedLockedReEncrypting)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(1000))
            .Build();

        // Warmup
        for (int i = 0; i < 100; i++)
        {
            using var x = new CyInt(42, pinnedOnlyPolicy);
        }

        var sw = new Stopwatch();

        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var x = new CyInt(42, pinnedOnlyPolicy);
        }
        sw.Stop();
        _pinnedOnlyTicks = sw.ElapsedTicks;

        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var x = new CyInt(42, pinnedLockedPolicy);
        }
        sw.Stop();
        _pinnedLockedTicks = sw.ElapsedTicks;

        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var x = new CyInt(42, pinnedLockedReEncPolicy);
        }
        sw.Stop();
        _pinnedLockedReEncTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintInfo($"PinnedOnly:               {_pinnedOnlyTicks,10} ticks  (baseline)");
        ConsoleHelpers.PrintInfo($"PinnedLocked:             {_pinnedLockedTicks,10} ticks  ({Factor(_pinnedOnlyTicks, _pinnedLockedTicks)}x)");
        ConsoleHelpers.PrintInfo($"PinnedLockedReEncrypting: {_pinnedLockedReEncTicks,10} ticks  ({Factor(_pinnedOnlyTicks, _pinnedLockedReEncTicks)}x)");
        Console.WriteLine();
    }

    // ── Section 3: Key Rotation Overhead ──
    private static long _noRotationTicks, _withRotationTicks;

    private static void BenchmarkKeyRotation()
    {
        ConsoleHelpers.PrintSubHeader("Key Rotation Overhead (500 iterations)");
        ConsoleHelpers.PrintNote("Comparing CyInt operations with vs without RotateKeyAndReEncrypt().");
        Console.WriteLine();

        const int iterations = 500;

        // Warmup
        for (int i = 0; i < 50; i++)
        {
            using var x = new CyInt(42, SecurityPolicy.Performance);
        }

        var sw = new Stopwatch();

        // Without rotation
        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var x = new CyInt(42, SecurityPolicy.Performance);
            using var y = new CyInt(17, SecurityPolicy.Performance);
            using var r = x + y;
        }
        sw.Stop();
        _noRotationTicks = sw.ElapsedTicks;

        // With rotation
        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var x = new CyInt(42, SecurityPolicy.Performance);
            x.RotateKeyAndReEncrypt();
            using var y = new CyInt(17, SecurityPolicy.Performance);
            using var r = x + y;
        }
        sw.Stop();
        _withRotationTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintInfo($"Without rotation: {_noRotationTicks,10} ticks");
        ConsoleHelpers.PrintInfo($"With rotation:    {_withRotationTicks,10} ticks  ({Factor(_noRotationTicks, _withRotationTicks)}x overhead)");
        Console.WriteLine();
    }

    // ── Section 4: FHE (BFV) vs AES-GCM ──
    private static long _fheEncTicks, _aesEncTicks;
    private static long _fheDecTicks, _aesDecTicks;
    private static long _fheAddTicks, _aesAddTicks;
    private static long _fheMulTicks;

    private static void BenchmarkFheVsAes()
    {
        ConsoleHelpers.PrintSubHeader("FHE (BFV) vs AES-GCM — Direct Engine Operations");
        ConsoleHelpers.PrintNote("FHE enables computation on encrypted data without decrypting.");
        ConsoleHelpers.PrintNote("FHE: 100 iterations | AES-GCM: 1,000 iterations");
        Console.WriteLine();

        const int fheIter = 100;
        const int aesIter = 1_000;

        // Setup FHE
        using var keyManager = new SealKeyManager();
        keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        using var fheEngine = new SealBfvEngine(keyManager);

        // Setup AES
        var aesEngine = new AesGcmEngine();
        var aesKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(aesKey);

        // Pre-compute ciphertexts
        var fheCtA = fheEngine.Encrypt(42);
        var fheCtB = fheEngine.Encrypt(17);
        var aesCtA = aesEngine.Encrypt(BitConverter.GetBytes(42), aesKey);
        var aesCtB = aesEngine.Encrypt(BitConverter.GetBytes(17), aesKey);

        var sw = new Stopwatch();

        // ── Encrypt ──
        // Warmup
        for (int i = 0; i < 5; i++) { _ = fheEngine.Encrypt(42); _ = aesEngine.Encrypt(BitConverter.GetBytes(42), aesKey); }

        sw.Restart();
        for (int i = 0; i < fheIter; i++) _ = fheEngine.Encrypt(42);
        sw.Stop();
        _fheEncTicks = sw.ElapsedTicks;

        sw.Restart();
        for (int i = 0; i < aesIter; i++) _ = aesEngine.Encrypt(BitConverter.GetBytes(42), aesKey);
        sw.Stop();
        _aesEncTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintInfo($"Encrypt   FHE({fheIter}): {_fheEncTicks,12} ticks | AES({aesIter}): {_aesEncTicks,12} ticks | per-op ratio: {PerOpFactor(_aesEncTicks, aesIter, _fheEncTicks, fheIter)}x");

        // ── Decrypt ──
        sw.Restart();
        for (int i = 0; i < fheIter; i++) _ = fheEngine.Decrypt(fheCtA);
        sw.Stop();
        _fheDecTicks = sw.ElapsedTicks;

        sw.Restart();
        for (int i = 0; i < aesIter; i++) _ = aesEngine.Decrypt(aesCtA, aesKey);
        sw.Stop();
        _aesDecTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintInfo($"Decrypt   FHE({fheIter}): {_fheDecTicks,12} ticks | AES({aesIter}): {_aesDecTicks,12} ticks | per-op ratio: {PerOpFactor(_aesDecTicks, aesIter, _fheDecTicks, fheIter)}x");

        // ── Add ──
        sw.Restart();
        for (int i = 0; i < fheIter; i++) _ = fheEngine.Add(fheCtA, fheCtB);
        sw.Stop();
        _fheAddTicks = sw.ElapsedTicks;

        sw.Restart();
        for (int i = 0; i < aesIter; i++)
        {
            var a = BitConverter.ToInt32(aesEngine.Decrypt(aesCtA, aesKey));
            var b = BitConverter.ToInt32(aesEngine.Decrypt(aesCtB, aesKey));
            _ = aesEngine.Encrypt(BitConverter.GetBytes(a + b), aesKey);
        }
        sw.Stop();
        _aesAddTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintInfo($"Add       FHE({fheIter}): {_fheAddTicks,12} ticks | AES({aesIter}): {_aesAddTicks,12} ticks | per-op ratio: {PerOpFactor(_aesAddTicks, aesIter, _fheAddTicks, fheIter)}x");

        // ── Multiply (FHE only — AES has no homomorphic multiply) ──
        sw.Restart();
        for (int i = 0; i < fheIter; i++) _ = fheEngine.Multiply(fheCtA, fheCtB);
        sw.Stop();
        _fheMulTicks = sw.ElapsedTicks;

        ConsoleHelpers.PrintInfo($"Multiply  FHE({fheIter}): {_fheMulTicks,12} ticks | AES: N/A (requires decrypt-compute-encrypt)");

        // ── Noise Budget ──
        var freshCt = fheEngine.Encrypt(42);
        int freshBudget = fheEngine.GetNoiseBudget(freshCt);
        var afterAdd = fheEngine.Add(fheCtA, fheCtB);
        int addBudget = fheEngine.GetNoiseBudget(afterAdd);
        var afterMul = fheEngine.Multiply(fheCtA, fheCtB);
        int mulBudget = fheEngine.GetNoiseBudget(afterMul);

        Console.WriteLine();
        ConsoleHelpers.PrintNote($"Noise budget — Fresh: {freshBudget} bits | After Add: {addBudget} bits | After Multiply: {mulBudget} bits");
        ConsoleHelpers.PrintNote("Noise budget decreases with operations. When it reaches 0, decryption fails.");
        Console.WriteLine();
    }

    // ── Section 5: CyInt with HomomorphicBasic vs SecureEnclave ──
    private static long _homoAddTicks, _enclaveAddTicks;

    private static void BenchmarkHomomorphicVsSecureEnclave()
    {
        ConsoleHelpers.PrintSubHeader("CyInt: HomomorphicBasic vs SecureEnclave (500 iterations)");
        ConsoleHelpers.PrintNote("HomomorphicBasic uses FHE engine for addition on encrypted data.");
        ConsoleHelpers.PrintNote("SecureEnclave decrypts, computes, re-encrypts in pinned memory.");
        Console.WriteLine();

        const int iterations = 500;

        // Configure FHE engine globally
        using var keyManager = new SealKeyManager();
        keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        using var fheEngine = new SealBfvEngine(keyManager);
        FheEngineProvider.Configure(fheEngine);

        try
        {
            // Warmup
            for (int i = 0; i < 10; i++)
            {
                using var a = new CyInt(42, SecurityPolicy.HomomorphicBasic);
                using var b = new CyInt(17, SecurityPolicy.HomomorphicBasic);
                using var r = a + b;
            }

            var sw = new Stopwatch();

            // HomomorphicBasic
            sw.Restart();
            for (int i = 0; i < iterations; i++)
            {
                using var a = new CyInt(42, SecurityPolicy.HomomorphicBasic);
                using var b = new CyInt(17, SecurityPolicy.HomomorphicBasic);
                using var r = a + b;
            }
            sw.Stop();
            _homoAddTicks = sw.ElapsedTicks;

            // SecureEnclave (Performance policy)
            sw.Restart();
            for (int i = 0; i < iterations; i++)
            {
                using var a = new CyInt(42, SecurityPolicy.Performance);
                using var b = new CyInt(17, SecurityPolicy.Performance);
                using var r = a + b;
            }
            sw.Stop();
            _enclaveAddTicks = sw.ElapsedTicks;

            ConsoleHelpers.PrintInfo($"HomomorphicBasic (FHE): {_homoAddTicks,12} ticks");
            ConsoleHelpers.PrintInfo($"SecureEnclave (AES):    {_enclaveAddTicks,12} ticks");
            ConsoleHelpers.PrintInfo($"FHE/AES ratio:          {Factor(_enclaveAddTicks, _homoAddTicks)}x");
            ConsoleHelpers.PrintNote("FHE is significantly slower but enables computation without ever decrypting.");
        }
        finally
        {
            // Reset global FHE engine to avoid side effects on other demos
            FheEngineProvider.Configure(null!);
        }

        Console.WriteLine();
    }

    // ── Summary Table ──
    private static void PrintSummaryTable()
    {
        ConsoleHelpers.PrintSubHeader("Summary: Security vs Performance Trade-offs");
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {"Protection Level",-35} {"Relative Cost",15}  Notes");
        Console.WriteLine($"  {new string('-', 80)}");
        Console.ResetColor();

        PrintTradeoffRow("Performance policy", "1.0x", "Fastest — PinnedOnly, no limits");
        PrintTradeoffRow("Balanced policy", $"{Factor(_perfTicks, _balTicks)}x", "Default — PinnedLocked, key rotation");
        PrintTradeoffRow("Maximum policy", $"{Factor(_perfTicks, _maxTicks)}x", "Strictest — PinnedLockedReEnc, limits");
        PrintTradeoffRow("PinnedOnly memory", "1.0x", "Pins buffers, no OS page lock");
        PrintTradeoffRow("PinnedLocked memory", $"{Factor(_pinnedOnlyTicks, _pinnedLockedTicks)}x", "Pins + locks pages in RAM");
        PrintTradeoffRow("PinnedLockedReEncrypting", $"{Factor(_pinnedOnlyTicks, _pinnedLockedReEncTicks)}x", "Pins + locks + periodic re-encrypt");
        PrintTradeoffRow("Key rotation", $"{Factor(_noRotationTicks, _withRotationTicks)}x", "HKDF key derivation + re-encrypt");
        PrintTradeoffRow("SecureEnclave (AES)", "1.0x", "Decrypt-compute-encrypt in enclave");
        PrintTradeoffRow("HomomorphicBasic (FHE)", $"{Factor(_enclaveAddTicks, _homoAddTicks)}x", "Compute on encrypted data — no decrypt");

        Console.WriteLine();
        ConsoleHelpers.PrintNote("Choose the protection level that matches your threat model.");
        ConsoleHelpers.PrintNote("FHE is ideal for untrusted environments; AES SecureEnclave for trusted local compute.");
    }

    // ── Helpers ──

    private static string Factor(long baseline, long measured)
    {
        if (baseline <= 0) return measured > 0 ? "∞" : "1.0";
        double f = (double)measured / baseline;
        return f < 10 ? f.ToString("F1", CultureInfo.InvariantCulture) : f.ToString("F0", CultureInfo.InvariantCulture);
    }

    private static string PerOpFactor(long baseTicks, int baseIter, long measuredTicks, int measuredIter)
    {
        double basePerOp = baseIter > 0 ? (double)baseTicks / baseIter : 0;
        double measuredPerOp = measuredIter > 0 ? (double)measuredTicks / measuredIter : 0;
        if (basePerOp <= 0) return "∞";
        double f = measuredPerOp / basePerOp;
        return f < 10 ? f.ToString("F1", CultureInfo.InvariantCulture) : f.ToString("F0", CultureInfo.InvariantCulture);
    }

    private static void PrintTradeoffRow(string level, string cost, string notes)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"  {level,-35}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($" {cost,15}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {notes}");
        Console.ResetColor();
    }
}
