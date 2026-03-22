using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Examples.Helpers;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;

namespace CyTypes.Examples.Demos;

public static class CkksFloatingPoint
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 15: CKKS Floating-Point FHE + Homomorphic Comparisons + String Equality");

        // --- Setup CKKS engine ---
        using var keyManager = new SealKeyManager();
        keyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
        using var ckksEngine = new SealCkksEngine(keyManager);

        // Setup BFV engine for comparison
        using var bfvKeyManager = new SealKeyManager();
        bfvKeyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        using var bfvEngine = new SealBfvEngine(bfvKeyManager);

        // Register engines
        FheEngineProvider.Configure(ckksEngine);
        FheEngineProvider.Configure(bfvEngine);
        FheEngineProvider.Configure(new SealComparisonEngine(bfvEngine, ckksEngine));

        // AES-SIV for string equality
        using var sivEngine = AesSivEngine.CreateWithRandomKey();
        FheEngineProvider.Configure(sivEngine);

        try
        {
            // --- CKKS floating-point arithmetic ---
            ConsoleHelpers.PrintNote("CKKS enables arithmetic on encrypted floating-point values.");
            Console.WriteLine();

            var policy = SecurityPolicy.HomomorphicBasic;
            var a = new CyDouble(3.14159, policy);
            var b = new CyDouble(2.71828, policy);

            Console.WriteLine($"  a = {a}");
            Console.WriteLine($"  b = {b}");

            var sum = a + b;
            var diff = a - b;
            var product = a * b;

            Console.WriteLine($"  a + b = {sum.ToInsecureDouble():F6}  (expected: 5.860070)");
            Console.WriteLine($"  a - b = {diff.ToInsecureDouble():F6}  (expected: 0.423310)");
            Console.WriteLine($"  a * b = {product.ToInsecureDouble():F4}  (expected: 8.5397)");
            Console.WriteLine();

            // --- CyFloat ---
            ConsoleHelpers.PrintNote("CyFloat works the same way with single precision.");
            var f1 = new CyFloat(100.5f, policy);
            var f2 = new CyFloat(0.5f, policy);
            var fSum = f1 + f2;
            Console.WriteLine($"  100.5f + 0.5f = {fSum.ToInsecureFloat():F2}  (expected: 101.00)");
            Console.WriteLine();

            // --- Homomorphic comparison (BFV) ---
            ConsoleHelpers.PrintNote("HomomorphicCircuit comparison: encrypted difference with sign extraction.");
            var compPolicy = new SecurityPolicyBuilder()
                .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
                .WithComparisonMode(ComparisonMode.HomomorphicCircuit)
                .WithMemoryProtection(MemoryProtection.PinnedLocked)
                .Build();

            var x = new CyInt(42, compPolicy);
            var y = new CyInt(17, compPolicy);

            Console.WriteLine($"  42 > 17 = {x > y}   (expected: True)");
            Console.WriteLine($"  42 == 17 = {x == y}  (expected: False)");
            Console.WriteLine($"  42 < 17 = {x < y}   (expected: False)");
            Console.WriteLine();

            // --- String equality ---
            ConsoleHelpers.PrintNote("HomomorphicEquality: AES-SIV deterministic encryption for string equality.");
            var strPolicy = new SecurityPolicyBuilder()
                .WithStringOperationMode(StringOperationMode.HomomorphicEquality)
                .WithMemoryProtection(MemoryProtection.PinnedLocked)
                .Build();

            var s1 = new CyString("secret-password", strPolicy);
            var s2 = new CyString("secret-password", strPolicy);
            var s3 = new CyString("different-value", strPolicy);

            Console.WriteLine($"  \"secret-password\" == \"secret-password\" = {s1 == s2}  (expected: True)");
            Console.WriteLine($"  \"secret-password\" == \"different-value\"  = {s1 == s3}  (expected: False)");
            Console.WriteLine();

            ConsoleHelpers.PrintNote("All operations completed on encrypted data without exposing plaintext.");
        }
        finally
        {
            FheEngineProvider.Reset();
        }

        Console.WriteLine();
    }
}
