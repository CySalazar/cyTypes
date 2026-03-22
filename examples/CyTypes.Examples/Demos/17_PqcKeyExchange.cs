using CyTypes.Core.Crypto.KeyExchange;
using CyTypes.Core.Crypto.Pqc;
using CyTypes.Examples.Helpers;

namespace CyTypes.Examples.Demos;

public static class PqcKeyExchange
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 17: Post-Quantum Key Exchange (ML-KEM-1024)");

        ConsoleHelpers.PrintNote("ML-KEM-1024 (FIPS 203, NIST Level 5) provides quantum-resistant key encapsulation.");
        ConsoleHelpers.PrintNote("cyTypes uses a hybrid scheme: ECDH P-256 + ML-KEM-1024 for forward secrecy.");
        Console.WriteLine();

        // --- Raw ML-KEM ---
        ConsoleHelpers.PrintSubHeader("ML-KEM-1024 Key Encapsulation");

        ConsoleHelpers.PrintCode("var mlkem = new MlKemKeyEncapsulation();");
        ConsoleHelpers.PrintCode("var (publicKey, secretKey) = mlkem.GenerateKeyPair();");
        var mlkem = new MlKemKeyEncapsulation();
        var (publicKey, secretKey) = mlkem.GenerateKeyPair();

        ConsoleHelpers.PrintInfo($"Public key:  {publicKey.Length:N0} bytes");
        ConsoleHelpers.PrintInfo($"Secret key:  {secretKey.Length:N0} bytes");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("var (ciphertext, sharedSecret) = mlkem.Encapsulate(publicKey);");
        var (ciphertext, sharedSecret) = mlkem.Encapsulate(publicKey);
        ConsoleHelpers.PrintInfo($"Ciphertext:    {ciphertext.Length:N0} bytes");
        ConsoleHelpers.PrintInfo($"Shared secret: {sharedSecret.Length} bytes (256 bits)");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("var recovered = mlkem.Decapsulate(ciphertext, secretKey);");
        var recovered = mlkem.Decapsulate(ciphertext, secretKey);
        bool match = sharedSecret.AsSpan().SequenceEqual(recovered);
        ConsoleHelpers.PrintSecure($"Shared secrets match: {match}");
        ConsoleHelpers.PrintNote("Both parties derive the same 256-bit secret without transmitting it.");
        Console.WriteLine();

        // --- Secure key pair holder ---
        ConsoleHelpers.PrintSubHeader("MlKemKeyPair — Secure Key Storage");

        ConsoleHelpers.PrintCode("using var keyPair = new MlKemKeyPair(publicKey, secretKey);");
        using var keyPair = new MlKemKeyPair(publicKey, secretKey);
        ConsoleHelpers.PrintSecure("Key material is pinned in memory; zeroed on Dispose().");
        Console.WriteLine();

        // --- Hybrid session key negotiation ---
        ConsoleHelpers.PrintSubHeader("Hybrid Key Exchange: ECDH P-256 + ML-KEM-1024");

        ConsoleHelpers.PrintNote("SessionKeyNegotiator combines classical ECDH with post-quantum ML-KEM");
        ConsoleHelpers.PrintNote("for defense-in-depth: secure even if one scheme is broken.");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("using var alice = new SessionKeyNegotiator();");
        ConsoleHelpers.PrintCode("using var bob = new SessionKeyNegotiator();");
        using var alice = new SessionKeyNegotiator();
        using var bob = new SessionKeyNegotiator();

        ConsoleHelpers.PrintCode("var aliceHandshake = alice.CreateHandshake();");
        ConsoleHelpers.PrintCode("var bobHandshake = bob.CreateHandshake();");
        var aliceHandshake = alice.CreateHandshake();
        var bobHandshake = bob.CreateHandshake();

        ConsoleHelpers.PrintInfo($"Alice ECDH key: {aliceHandshake.EcdhPublicKey.Length} bytes");
        ConsoleHelpers.PrintInfo($"Alice ML-KEM key: {aliceHandshake.MlKemPublicKey.Length:N0} bytes");
        Console.WriteLine();

        // Alice is initiator
        ConsoleHelpers.PrintCode("var (aliceKey, mlKemCt) = alice.DeriveSessionKeyAsInitiator(bobHandshake);");
        var (aliceKey, mlKemCt) = alice.DeriveSessionKeyAsInitiator(bobHandshake);

        // Bob is responder
        ConsoleHelpers.PrintCode("var bobKey = bob.DeriveSessionKeyAsResponder(aliceHandshake, mlKemCt);");
        using var bobKey = bob.DeriveSessionKeyAsResponder(aliceHandshake, mlKemCt);

        using (aliceKey)
        {
            bool keysMatch = aliceKey.AsReadOnlySpan().SequenceEqual(bobKey.AsReadOnlySpan());
            ConsoleHelpers.PrintSecure($"Session keys match: {keysMatch}");
            ConsoleHelpers.PrintInfo($"Session key length: {aliceKey.Length} bytes (256 bits)");
        }
        Console.WriteLine();

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("Key derivation: HKDF-SHA512(ecdh_shared || mlkem_shared)");
        ConsoleHelpers.PrintSecure("Quantum-safe today, classically secure as a fallback.");
    }
}
