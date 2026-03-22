using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Examples.Helpers;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;

namespace CyTypes.Examples.Demos;

public static class FheBfvArithmetic
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 16: FHE BFV — Integer Arithmetic on Encrypted Data");

        ConsoleHelpers.PrintNote("Fully Homomorphic Encryption (BFV) allows add, subtract, multiply, and negate");
        ConsoleHelpers.PrintNote("on encrypted integers WITHOUT ever decrypting them.");
        Console.WriteLine();

        // --- Setup ---
        ConsoleHelpers.PrintSubHeader("SEAL BFV Engine Setup");

        ConsoleHelpers.PrintCode("var keyManager = new SealKeyManager();");
        ConsoleHelpers.PrintCode("keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());");
        ConsoleHelpers.PrintCode("var engine = new SealBfvEngine(keyManager);");
        ConsoleHelpers.PrintCode("FheEngineProvider.Configure(engine);");

        using var keyManager = new SealKeyManager();
        keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        using var engine = new SealBfvEngine(keyManager);
        FheEngineProvider.Configure(engine);
        ConsoleHelpers.PrintSecure("BFV engine initialized with 128-bit security.");
        Console.WriteLine();

        try
        {
            var policy = SecurityPolicy.HomomorphicBasic;

            // --- Addition ---
            ConsoleHelpers.PrintSubHeader("Homomorphic Addition");

            ConsoleHelpers.PrintCode("var a = new CyInt(100, SecurityPolicy.HomomorphicBasic);");
            ConsoleHelpers.PrintCode("var b = new CyInt(250, SecurityPolicy.HomomorphicBasic);");
            ConsoleHelpers.PrintCode("var sum = a + b;  // computed on ciphertext!");

            using var a = new CyInt(100, policy);
            using var b = new CyInt(250, policy);
            using var sum = a + b;

            ConsoleHelpers.PrintSecure($"sum.IsCompromised = {sum.IsCompromised}");
            ConsoleHelpers.PrintNote("The result is encrypted — no plaintext was ever exposed during the operation.");
            ConsoleHelpers.PrintCode("sum.ToInsecureInt()  // decrypt to verify");
            ConsoleHelpers.PrintInfo($"=> {sum.ToInsecureInt()} (expected: 350)");
            Console.WriteLine();

            // --- Subtraction ---
            ConsoleHelpers.PrintSubHeader("Homomorphic Subtraction");

            ConsoleHelpers.PrintCode("var diff = a - b;");
            using var diff = a - b;
            ConsoleHelpers.PrintInfo($"=> {diff.ToInsecureInt()} (expected: -150)");
            Console.WriteLine();

            // --- Multiplication ---
            ConsoleHelpers.PrintSubHeader("Homomorphic Multiplication");

            ConsoleHelpers.PrintCode("var x = new CyInt(7, policy);");
            ConsoleHelpers.PrintCode("var y = new CyInt(6, policy);");
            ConsoleHelpers.PrintCode("var product = x * y;");

            using var x = new CyInt(7, policy);
            using var y = new CyInt(6, policy);
            using var product = x * y;
            ConsoleHelpers.PrintInfo($"=> {product.ToInsecureInt()} (expected: 42)");
            Console.WriteLine();

            // --- Negation ---
            ConsoleHelpers.PrintSubHeader("Homomorphic Negation");

            ConsoleHelpers.PrintCode("var neg = -x;");
            using var neg = -x;
            ConsoleHelpers.PrintInfo($"=> {neg.ToInsecureInt()} (expected: -7)");
            Console.WriteLine();

            // --- Noise budget ---
            ConsoleHelpers.PrintSubHeader("Noise Budget Monitoring");

            ConsoleHelpers.PrintNote("Every FHE ciphertext has a noise budget. Operations consume it.");
            ConsoleHelpers.PrintNote("When budget reaches zero, decryption gives incorrect results.");

            var encrypted = engine.Encrypt(42);
            int budgetBefore = engine.GetNoiseBudget(encrypted);
            ConsoleHelpers.PrintInfo($"After encrypt: noise budget = {budgetBefore} bits");

            var doubled = engine.Add(encrypted, encrypted);
            int budgetAfterAdd = engine.GetNoiseBudget(doubled);
            ConsoleHelpers.PrintInfo($"After add:     noise budget = {budgetAfterAdd} bits");

            var squared = engine.Multiply(encrypted, encrypted);
            int budgetAfterMul = engine.GetNoiseBudget(squared);
            ConsoleHelpers.PrintInfo($"After multiply: noise budget = {budgetAfterMul} bits");

            ConsoleHelpers.PrintNote("Multiplication is far more expensive than addition in terms of noise.");
            Console.WriteLine();

            // --- Key bundle export ---
            ConsoleHelpers.PrintSubHeader("Key Bundle Export");

            ConsoleHelpers.PrintCode("var bundle = keyManager.ExportKeyBundle();");
            using var bundle = keyManager.ExportKeyBundle();
            ConsoleHelpers.PrintInfo($"Public key:  {bundle.PublicKey.Length:N0} bytes");
            ConsoleHelpers.PrintInfo($"Secret key:  {bundle.SecretKey.Length:N0} bytes");
            ConsoleHelpers.PrintInfo($"Relin keys:  {bundle.RelinKeys.Length:N0} bytes");
            ConsoleHelpers.PrintNote("Keys can be serialized for storage or distributed to computing parties.");
            Console.WriteLine();

            ConsoleHelpers.PrintLine();
            ConsoleHelpers.PrintSecure("All arithmetic was performed on ciphertexts — the server never saw plaintext.");
        }
        finally
        {
            FheEngineProvider.Reset();
        }
    }
}
