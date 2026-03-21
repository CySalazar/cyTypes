using CyTypes.Examples.Demos;

namespace CyTypes.Examples;

public static class Program
{
    private static readonly (string Name, Action Run)[] Demos =
    [
        ("Basic Usage - CyTypes vs .NET Primitives", BasicUsage.Run),
        ("Memory Dump Exposure", MemoryDumpExposure.Run),
        ("String Interning Risk", StringInterningRisk.Run),
        ("Taint Tracking", TaintTracking.Run),
        ("Security Policies", SecurityPolicies.Run),
        ("Auto-Destroy and Rate Limiting", AutoDestroyAndRateLimiting.Run),
        ("Key Rotation", KeyRotation.Run),
        ("Timing Attack Resistance", TimingAttacks.Run),
        ("All 10 Types Showcase", AllTypesShowcase.Run),
        ("Performance Overhead - CyTypes vs Native C#", PerformanceOverhead.Run),
        ("Protection Level Benchmarks", ProtectionLevelBenchmarks.Run),
        ("EF Core Integration", EfCoreIntegration.Run),
        ("JSON Serialization", JsonSerialization.Run),
        ("Stream Encryption", StreamEncryption.Run),
    ];

    public static void Main(string[] args)
    {
        if (args.Length > 0)
        {
            if (args[0].Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                RunAll();
                return;
            }

            if (int.TryParse(args[0], out int demoNumber) && demoNumber >= 1 && demoNumber <= Demos.Length)
            {
                RunDemo(demoNumber);
                return;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Invalid argument: {args[0]}. Use a number 1-{Demos.Length} or \"all\".");
            Console.ResetColor();
            return;
        }

        RunInteractive();
    }

    private static void RunInteractive()
    {
        while (true)
        {
            PrintMenu();
            Console.Write($"  Select demo (1-{Demos.Length}, 'all', or 'q' to quit): ");
            string? input = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(input) || input.Equals("q", StringComparison.OrdinalIgnoreCase))
                break;

            if (input.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                RunAll();
                WaitForKey();
                continue;
            }

            if (int.TryParse(input, out int choice) && choice >= 1 && choice <= Demos.Length)
            {
                RunDemo(choice);
                WaitForKey();
                continue;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Invalid choice. Enter 1-{Demos.Length}, 'all', or 'q'.");
            Console.ResetColor();
        }
    }

    private static void PrintMenu()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine();
        Console.WriteLine("  ╔══════════════════════════════════════════════════╗");
        Console.WriteLine("  ║            cyTypes - Usage Examples             ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        for (int i = 0; i < Demos.Length; i++)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"  [{i + 1}] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(Demos[i].Name);
        }

        Console.ResetColor();
        Console.WriteLine();
    }

    private static void RunDemo(int number)
    {
        try
        {
            Demos[number - 1].Run();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Demo {number} failed: {ex.GetType().Name}: {ex.Message}");
            Console.ResetColor();
        }
    }

    private static void RunAll()
    {
        for (int i = 1; i <= Demos.Length; i++)
        {
            RunDemo(i);
            Console.WriteLine();
        }
    }

    private static void WaitForKey()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine();
        Console.WriteLine("  Press any key to return to menu...");
        Console.ResetColor();

        if (!Console.IsInputRedirected)
            Console.ReadKey(true);
    }
}
