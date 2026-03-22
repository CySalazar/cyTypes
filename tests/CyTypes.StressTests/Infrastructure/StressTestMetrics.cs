using System.Collections.Concurrent;
using System.Diagnostics;

namespace CyTypes.StressTests.Infrastructure;

/// <summary>
/// Thread-safe metrics collector for stress tests.
/// </summary>
public sealed class StressTestMetrics
{
    private readonly ConcurrentDictionary<string, long> _counters = new();
    private readonly ConcurrentDictionary<string, ConcurrentBag<double>> _latencies = new();
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();

    public void IncrementCounter(string name, long amount = 1)
    {
        _counters.AddOrUpdate(name, amount, (_, old) => old + amount);
    }

    public void RecordLatency(string name, TimeSpan elapsed)
    {
        var bag = _latencies.GetOrAdd(name, _ => new ConcurrentBag<double>());
        bag.Add(elapsed.TotalMilliseconds);
    }

    public long GetCounter(string name) => _counters.GetValueOrDefault(name, 0);

    public TimeSpan Elapsed => _stopwatch.Elapsed;

    public double GetOpsPerSecond(string counterName)
    {
        var count = GetCounter(counterName);
        var seconds = _stopwatch.Elapsed.TotalSeconds;
        return seconds > 0 ? count / seconds : 0;
    }

    public LatencyStats? GetLatencyStats(string name)
    {
        if (!_latencies.TryGetValue(name, out var bag) || bag.IsEmpty)
            return null;

        var sorted = bag.OrderBy(x => x).ToList();
        return new LatencyStats
        {
            Min = sorted[0],
            Max = sorted[^1],
            Avg = sorted.Average(),
            P50 = sorted[(int)(sorted.Count * 0.50)],
            P99 = sorted[(int)(sorted.Count * 0.99)],
            Count = sorted.Count
        };
    }

    public string GetSummary()
    {
        var lines = new List<string> { $"Duration: {_stopwatch.Elapsed.TotalSeconds:F2}s", "" };

        if (!_counters.IsEmpty)
        {
            lines.Add("Counters:");
            foreach (var (key, value) in _counters.OrderBy(x => x.Key))
                lines.Add($"  {key}: {value:N0} ({GetOpsPerSecond(key):N0} ops/s)");
            lines.Add("");
        }

        if (!_latencies.IsEmpty)
        {
            lines.Add("Latencies (ms):");
            foreach (var (key, _) in _latencies.OrderBy(x => x.Key))
            {
                var stats = GetLatencyStats(key);
                if (stats != null)
                    lines.Add($"  {key}: min={stats.Min:F2} avg={stats.Avg:F2} p50={stats.P50:F2} p99={stats.P99:F2} max={stats.Max:F2} (n={stats.Count})");
            }
        }

        return string.Join(Environment.NewLine, lines);
    }
}

public sealed class LatencyStats
{
    public double Min { get; init; }
    public double Max { get; init; }
    public double Avg { get; init; }
    public double P50 { get; init; }
    public double P99 { get; init; }
    public int Count { get; init; }
}
