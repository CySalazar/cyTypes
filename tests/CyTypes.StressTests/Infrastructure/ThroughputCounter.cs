using System.Diagnostics;

namespace CyTypes.StressTests.Infrastructure;

/// <summary>
/// Atomic counter with stopwatch for measuring ops/sec in soak tests.
/// </summary>
public sealed class ThroughputCounter
{
    private long _count;
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();

    public long Count => Interlocked.Read(ref _count);

    public void Increment() => Interlocked.Increment(ref _count);

    public void Add(long amount) => Interlocked.Add(ref _count, amount);

    public double OpsPerSecond
    {
        get
        {
            var seconds = _stopwatch.Elapsed.TotalSeconds;
            return seconds > 0 ? Interlocked.Read(ref _count) / seconds : 0;
        }
    }

    public TimeSpan Elapsed => _stopwatch.Elapsed;

    public void Reset()
    {
        Interlocked.Exchange(ref _count, 0);
        _stopwatch.Restart();
    }

    public string Summary => $"{Count:N0} ops in {Elapsed.TotalSeconds:F2}s ({OpsPerSecond:N0} ops/s)";
}
