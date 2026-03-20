using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class KeyRotation
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 7: Key Rotation and Re-Encryption");

        ConsoleHelpers.PrintNote("Key rotation limits blast radius of a compromised key and satisfies compliance");
        ConsoleHelpers.PrintNote("requirements (PCI-DSS, HIPAA, SOC2). Also bounds data encrypted per key.");
        Console.WriteLine();

        // --- RotateKeyAndReEncrypt ---
        ConsoleHelpers.PrintSubHeader("Key Rotation with RotateKeyAndReEncrypt()");

        ConsoleHelpers.PrintCode("var secret = new CyInt(42);");
        using var secret = new CyInt(42);

        ConsoleHelpers.PrintCode("secret.ToString()");
        ConsoleHelpers.PrintInfo($"=> {secret}");

        ConsoleHelpers.PrintCode("secret.ToInsecureInt()");
        int valueBefore = secret.ToInsecureInt();
        ConsoleHelpers.PrintInfo($"=> {valueBefore}");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("secret.RotateKeyAndReEncrypt();");
        secret.RotateKeyAndReEncrypt();
        ConsoleHelpers.PrintSecure("Key rotated!");

        ConsoleHelpers.PrintCode("secret.ToString()  // after rotation");
        ConsoleHelpers.PrintInfo($"=> {secret}");
        ConsoleHelpers.PrintNote("Atomic process: decrypt with old key -> derive new key via HKDF -> re-encrypt.");
        ConsoleHelpers.PrintNote("Old key material zeroed immediately. Plaintext never exposed to managed memory.");

        ConsoleHelpers.PrintCode("secret.ToInsecureInt()  // value preserved?");
        int valueAfter = secret.ToInsecureInt();
        ConsoleHelpers.PrintSecure($"=> {valueAfter} (match: {valueBefore == valueAfter})");
        Console.WriteLine();

        // --- Multiple rotations ---
        ConsoleHelpers.PrintSubHeader("Multiple Consecutive Rotations");

        ConsoleHelpers.PrintCode("var multiRotate = new CyInt(12345);");
        using var multiRotate = new CyInt(12345);

        for (int i = 1; i <= 5; i++)
        {
            ConsoleHelpers.PrintCode($"multiRotate.RotateKeyAndReEncrypt();  // rotation #{i}");
            multiRotate.RotateKeyAndReEncrypt();
            ConsoleHelpers.PrintInfo($"=> value = {multiRotate.ToInsecureInt()}");
        }
        ConsoleHelpers.PrintSecure("Value preserved across all 5 rotations.");
        Console.WriteLine();

        // --- ReEncryptWithCurrentKey ---
        ConsoleHelpers.PrintSubHeader("Re-Encrypt Without Key Rotation");
        ConsoleHelpers.PrintNote("Same key, new ciphertext + IV. Prevents ciphertext correlation attacks:");
        ConsoleHelpers.PrintNote("two dumps show completely different ciphertext for the same value.");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("var reencrypt = new CyInt(999);");
        using var reencrypt = new CyInt(999);

        ConsoleHelpers.PrintCode("reencrypt.ToString()  // before");
        ConsoleHelpers.PrintInfo($"=> {reencrypt}");

        ConsoleHelpers.PrintCode("reencrypt.ReEncryptWithCurrentKey();");
        reencrypt.ReEncryptWithCurrentKey();

        ConsoleHelpers.PrintCode("reencrypt.ToInsecureInt()");
        ConsoleHelpers.PrintSecure($"=> {reencrypt.ToInsecureInt()}");
        Console.WriteLine();

        // --- String key rotation ---
        ConsoleHelpers.PrintSubHeader("Key Rotation on CyString");

        ConsoleHelpers.PrintCode("var cyStr = new CyString(\"TopSecretMessage\");");
        using var cyStr = new CyString("TopSecretMessage");

        ConsoleHelpers.PrintCode("cyStr.ToString()  // before");
        ConsoleHelpers.PrintInfo($"=> {cyStr}");

        ConsoleHelpers.PrintCode("cyStr.RotateKeyAndReEncrypt();");
        cyStr.RotateKeyAndReEncrypt();

        ConsoleHelpers.PrintCode("cyStr.ToInsecureString()  // value preserved?");
        string decrypted = cyStr.ToInsecureString();
        ConsoleHelpers.PrintSecure($"=> \"{decrypted}\"");
        Console.WriteLine();

        // --- Security explanation ---
        ConsoleHelpers.PrintSubHeader("Why Key Rotation Matters");
        ConsoleHelpers.PrintSecure("1. Old ciphertext + old key become useless after rotation");
        ConsoleHelpers.PrintSecure("2. New key derived via HKDF from current key material");
        ConsoleHelpers.PrintSecure("3. Limits damage window if a key is compromised");
        ConsoleHelpers.PrintSecure("4. Can be automated via KeyRotationPolicy (e.g., every N operations)");
    }
}
