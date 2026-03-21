using System.Globalization;
using Microsoft.Diagnostics.Runtime;

namespace CyTypes.Tools.HeapAnalysis;

public class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("CyTypes Heap Analysis Tool");
            Console.WriteLine("Usage:");
            Console.WriteLine("  heap-analysis scan <pid> <hex-pattern>  - Scan for byte pattern in process heap");
            Console.WriteLine("  heap-analysis validate <pid>            - Validate disposed SecureBuffers are zeroed");
            Console.WriteLine("  heap-analysis self-test                 - Run self-analysis on current process");
            return 1;
        }

        return args[0].ToLowerInvariant() switch
        {
            "scan" => RunScan(args),
            "validate" => RunValidate(args),
            "self-test" => RunSelfTest(),
            _ => PrintUnknownCommand(args[0])
        };
    }

    private static int RunScan(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("Usage: scan <pid> <hex-pattern>");
            return 1;
        }

        var pid = int.Parse(args[1], CultureInfo.InvariantCulture);
        var pattern = Convert.FromHexString(args[2]);

        using var target = DataTarget.AttachToProcess(pid, suspend: true);
        var matches = HeapScanner.ScanForPattern(target, pattern);

        Console.WriteLine($"Found {matches.Count} matches for pattern {args[2]}:");
        foreach (var match in matches)
        {
            Console.WriteLine($"  Address: 0x{match.Address:X16}, Size: {match.Length}, Type: {match.TypeName}");
        }

        return matches.Count > 0 ? 1 : 0;
    }

    private static int RunValidate(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: validate <pid>");
            return 1;
        }

        var pid = int.Parse(args[1], CultureInfo.InvariantCulture);
        using var target = DataTarget.AttachToProcess(pid, suspend: true);
        var report = HeapScanner.ValidateSecureBuffers(target);

        Console.WriteLine("SecureBuffer Validation Report:");
        Console.WriteLine($"  Total found: {report.TotalFound}");
        Console.WriteLine($"  Properly zeroed: {report.ProperlyZeroed}");
        Console.WriteLine($"  Still contains data: {report.StillContainsData}");

        foreach (var violation in report.Violations)
        {
            Console.Error.WriteLine($"  VIOLATION: 0x{violation.Address:X16} ({violation.Length} bytes) - {violation.TypeName}");
        }

        return report.Violations.Count > 0 ? 1 : 0;
    }

    private static int RunSelfTest()
    {
        Console.WriteLine("Running self-test with current process...");
        var pid = Environment.ProcessId;

        using var target = DataTarget.CreateSnapshotAndAttach(pid);
        var report = HeapScanner.ValidateSecureBuffers(target);

        Console.WriteLine($"Self-test complete. SecureBuffers found: {report.TotalFound}, Violations: {report.Violations.Count}");
        return report.Violations.Count > 0 ? 1 : 0;
    }

    private static int PrintUnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"Unknown command: {cmd}");
        return 1;
    }
}
