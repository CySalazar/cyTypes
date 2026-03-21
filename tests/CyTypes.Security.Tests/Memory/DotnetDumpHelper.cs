using System.Diagnostics;

namespace CyTypes.Security.Tests.Memory;

/// <summary>
/// Helper for programmatic invocation of dotnet-dump for memory analysis.
/// Tests using this helper should be tagged with [Trait("Category", "MemoryAnalysis")]
/// to allow exclusion from fast CI runs.
/// </summary>
public static class DotnetDumpHelper
{
    public static bool IsAvailable()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "dotnet-dump",
                Arguments = "--version",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            process?.WaitForExit(5000);
            return process?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static string? CollectDump(int processId, string outputPath)
    {
        var dumpPath = Path.Combine(outputPath, $"dump_{processId}_{DateTime.UtcNow:yyyyMMddHHmmss}.dmp");

        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "dotnet-dump",
            Arguments = $"collect -p {processId} -o \"{dumpPath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });

        process?.WaitForExit(30000);
        return process?.ExitCode == 0 ? dumpPath : null;
    }

    public static string? AnalyzeDump(string dumpPath, string command)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "dotnet-dump",
            Arguments = $"analyze \"{dumpPath}\"",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });

        if (process == null) return null;

        process.StandardInput.WriteLine(command);
        process.StandardInput.WriteLine("exit");
        process.WaitForExit(30000);

        return process.StandardOutput.ReadToEnd();
    }
}
