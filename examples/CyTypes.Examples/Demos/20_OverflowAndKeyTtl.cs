using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class OverflowAndKeyTtl
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 20: Overflow Mode + Key TTL / Expiration");

        // --- Overflow Mode ---
        ConsoleHelpers.PrintSubHeader("OverflowMode.Checked — Detect Integer Overflow");

        ConsoleHelpers.PrintNote("SecurityPolicy.Maximum uses OverflowMode.Checked by default.");
        ConsoleHelpers.PrintNote("Arithmetic that overflows throws OverflowException instead of wrapping silently.");
        Console.WriteLine();

        var checkedPolicy = new SecurityPolicyBuilder()
            .WithOverflowMode(OverflowMode.Checked)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .Build();

        ConsoleHelpers.PrintCode("var maxVal = new CyInt(int.MaxValue, checkedPolicy);");
        ConsoleHelpers.PrintCode("var one = new CyInt(1, checkedPolicy);");
        ConsoleHelpers.PrintCode("var overflow = maxVal + one;  // throws!");

        using var maxVal = new CyInt(int.MaxValue, checkedPolicy);
        using var one = new CyInt(1, checkedPolicy);

        try
        {
            using var overflow = maxVal + one;
            ConsoleHelpers.PrintRisk("Overflow was NOT detected (unexpected).");
        }
        catch (OverflowException ex)
        {
            ConsoleHelpers.PrintSecure($"OverflowException caught: {ex.Message}");
        }
        Console.WriteLine();

        // --- Unchecked mode ---
        ConsoleHelpers.PrintSubHeader("OverflowMode.Unchecked — Silent Wrapping (Default)");

        var uncheckedPolicy = new SecurityPolicyBuilder()
            .WithOverflowMode(OverflowMode.Unchecked)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .Build();

        using var maxVal2 = new CyInt(int.MaxValue, uncheckedPolicy);
        using var one2 = new CyInt(1, uncheckedPolicy);
        using var wrapped = maxVal2 + one2;

        ConsoleHelpers.PrintCode("// With OverflowMode.Unchecked:");
        ConsoleHelpers.PrintCode("var wrapped = maxVal + one;");
        ConsoleHelpers.PrintInfo($"Result: {wrapped.ToInsecureInt()} (wrapped to int.MinValue)");
        ConsoleHelpers.PrintNote("Default Balanced policy uses Unchecked — wraps like standard .NET.");
        Console.WriteLine();

        // --- Key TTL ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Key TTL / Expiration");

        ConsoleHelpers.PrintNote("KeyManager supports time-to-live: after TTL, CurrentKey throws KeyExpiredException.");
        ConsoleHelpers.PrintNote("This enforces mandatory key rotation and limits exposure windows.");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("var km = new KeyManager(TimeSpan.FromSeconds(2));");
        using var km = new KeyManager(TimeSpan.FromSeconds(2));

        ConsoleHelpers.PrintInfo($"Key ID:      {km.KeyId}");
        ConsoleHelpers.PrintInfo($"TTL:         {km.Ttl}");
        ConsoleHelpers.PrintInfo($"Is expired:  {km.IsExpired}");
        ConsoleHelpers.PrintInfo($"Key created: {km.KeyCreatedUtc:HH:mm:ss.fff} UTC");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("// Accessing key before TTL — works fine");
        _ = km.CurrentKey;
        ConsoleHelpers.PrintSecure("CurrentKey accessed successfully.");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("Thread.Sleep(2100);  // wait for TTL to expire");
        ConsoleHelpers.PrintNote("Waiting for key to expire...");
        Thread.Sleep(2100);

        ConsoleHelpers.PrintInfo($"Is expired:  {km.IsExpired}");
        ConsoleHelpers.PrintCode("_ = km.CurrentKey;  // throws KeyExpiredException!");
        try
        {
            _ = km.CurrentKey;
            ConsoleHelpers.PrintRisk("Key was NOT expired (unexpected).");
        }
        catch (KeyExpiredException ex)
        {
            ConsoleHelpers.PrintSecure($"KeyExpiredException: {ex.Message}");
        }
        Console.WriteLine();

        // --- Key rotation resets TTL ---
        ConsoleHelpers.PrintSubHeader("Key Rotation Resets TTL");

        ConsoleHelpers.PrintCode("km.RotateKey();  // derives new key, resets TTL");
        km.RotateKey();
        ConsoleHelpers.PrintInfo($"New Key ID:  {km.KeyId}");
        ConsoleHelpers.PrintInfo($"Is expired:  {km.IsExpired}");
        _ = km.CurrentKey;
        ConsoleHelpers.PrintSecure("CurrentKey accessible again after rotation.");
        Console.WriteLine();

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("OverflowMode prevents silent integer bugs in high-security contexts.");
        ConsoleHelpers.PrintSecure("Key TTL enforces rotation schedules and limits compromise windows.");
    }
}
