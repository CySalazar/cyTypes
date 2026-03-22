using System.Diagnostics;

namespace CyTypes.StressTests.Infrastructure;

/// <summary>
/// Tracks memory usage across test phases to detect leaks.
/// </summary>
public sealed class MemoryTracker
{
    public record MemorySnapshot(
        long TotalMemory,
        long WorkingSet,
        int Gen0Collections,
        int Gen1Collections,
        int Gen2Collections);

    public static MemorySnapshot TakeSnapshot(bool forceGc = false)
    {
        if (forceGc)
        {
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true);
        }

        return new MemorySnapshot(
            TotalMemory: GC.GetTotalMemory(forceGc),
            WorkingSet: Process.GetCurrentProcess().WorkingSet64,
            Gen0Collections: GC.CollectionCount(0),
            Gen1Collections: GC.CollectionCount(1),
            Gen2Collections: GC.CollectionCount(2));
    }

    public static long MemoryDelta(MemorySnapshot before, MemorySnapshot after)
        => after.TotalMemory - before.TotalMemory;

    /// <summary>
    /// Returns true if the memory delta after cleanup exceeds the tolerance percentage of baseline.
    /// </summary>
    public static bool HasLeak(MemorySnapshot baseline, MemorySnapshot afterCleanup, double tolerancePercent = 5.0)
    {
        var delta = afterCleanup.TotalMemory - baseline.TotalMemory;
        var threshold = baseline.TotalMemory * (tolerancePercent / 100.0);
        return delta > threshold;
    }

    public static string FormatSnapshot(string label, MemorySnapshot snapshot)
        => $"{label}: TotalMemory={snapshot.TotalMemory / 1024.0 / 1024.0:F2}MB, " +
           $"WorkingSet={snapshot.WorkingSet / 1024.0 / 1024.0:F2}MB, " +
           $"GC[{snapshot.Gen0Collections}/{snapshot.Gen1Collections}/{snapshot.Gen2Collections}]";
}
