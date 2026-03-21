using System.Diagnostics;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks.Application.Soak;

/// <summary>
/// Soak test runner for CyTypes memory leak detection.
/// Creates and disposes CyTypes instances continuously for a configurable duration.
/// Run via: dotnet run --project CyTypes.Benchmarks.Application -- soak [minutes]
/// </summary>
public static class SoakTestRunner
{
    public static int Run(int durationMinutes = 30)
    {
        var duration = TimeSpan.FromMinutes(durationMinutes);
        var samplingInterval = TimeSpan.FromSeconds(30);
        var detector = new MemoryLeakDetector(samplingInterval);

        var sw = Stopwatch.StartNew();
        long operationCount = 0;

        Console.WriteLine($"Starting soak test for {durationMinutes} minutes...");

        while (sw.Elapsed < duration)
        {
            for (int i = 0; i < 1000; i++)
            {
                using var cyStr = new CyString($"soak-test-{operationCount}");
                _ = cyStr.ToInsecureString();

                using var cyInt = new CyInt(i);
                _ = cyInt.ToInsecureInt();

                using var cyDec = new CyDecimal(i * 1.5m);
                _ = cyDec.ToInsecureDecimal();

                operationCount++;
            }

            detector.Sample();

            if (operationCount % 100000 == 0)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                Console.WriteLine(
                    $"[{sw.Elapsed:hh\\:mm\\:ss}] Ops: {operationCount:N0}, " +
                    $"Memory: {GC.GetTotalMemory(false) / 1024.0 / 1024.0:F2} MB, " +
                    $"GC Gen0: {GC.CollectionCount(0)}, Gen1: {GC.CollectionCount(1)}, Gen2: {GC.CollectionCount(2)}");
            }
        }

        var isStable = detector.IsMemoryStable(maxGrowthRateMbPerHour: 10.0);
        Console.WriteLine($"Soak test completed. Operations: {operationCount:N0}, Memory stable: {isStable}");

        return isStable ? 0 : 1;
    }
}
