namespace CyTypes.Benchmarks.Application.Soak;

/// <summary>
/// Samples memory usage at intervals and performs linear regression
/// to detect memory leaks based on growth rate.
/// </summary>
public class MemoryLeakDetector
{
    private readonly TimeSpan _samplingInterval;
    private readonly List<(TimeSpan elapsed, long bytes)> _samples = new();
    private readonly System.Diagnostics.Stopwatch _stopwatch;

    public MemoryLeakDetector(TimeSpan samplingInterval)
    {
        _samplingInterval = samplingInterval;
        _stopwatch = System.Diagnostics.Stopwatch.StartNew();
    }

    public void Sample()
    {
        var elapsed = _stopwatch.Elapsed;

        if (_samples.Count > 0)
        {
            var lastSample = _samples[^1];
            if (elapsed - lastSample.elapsed < _samplingInterval)
                return;
        }

        var memory = GC.GetTotalMemory(forceFullCollection: false);
        _samples.Add((elapsed, memory));
    }

    /// <summary>
    /// Determines if memory usage is stable using linear regression.
    /// </summary>
    /// <param name="maxGrowthRateMbPerHour">Maximum acceptable growth rate in MB/hour.</param>
    /// <returns>True if the growth rate is within the threshold.</returns>
    public bool IsMemoryStable(double maxGrowthRateMbPerHour)
    {
        if (_samples.Count < 3)
            return true; // Not enough data

        // Skip the first 10% of samples (warm-up period)
        var warmupCount = Math.Max(1, _samples.Count / 10);
        var stableSamples = _samples.Skip(warmupCount).ToList();

        if (stableSamples.Count < 2)
            return true;

        // Linear regression: y = mx + b
        var n = stableSamples.Count;
        var xs = stableSamples.Select(s => s.elapsed.TotalHours).ToArray();
        var ys = stableSamples.Select(s => s.bytes / (1024.0 * 1024.0)).ToArray(); // MB

        var sumX = xs.Sum();
        var sumY = ys.Sum();
        var sumXY = xs.Zip(ys, (x, y) => x * y).Sum();
        var sumX2 = xs.Select(x => x * x).Sum();

        var slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);

        Console.WriteLine($"Memory growth rate: {slope:F4} MB/hour (threshold: {maxGrowthRateMbPerHour} MB/hour)");

        return slope <= maxGrowthRateMbPerHour;
    }

    public IReadOnlyList<(TimeSpan elapsed, long bytes)> GetSamples() => _samples.AsReadOnly();
}
