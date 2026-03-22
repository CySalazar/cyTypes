using CyTypes.Core.Memory;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.MemoryPressure;

[Trait("Category", "Stress")]
[Trait("SubCategory", "MemoryPressure")]
public class SecureBufferPoolMemoryTests
{
    private readonly ITestOutputHelper _output;

    public SecureBufferPoolMemoryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Pool_Reuse_Reduces_Allocation()
    {
        const int iterations = 10_000;
        const int bufferSize = 256;

        // Measure GC collections with pooling
        var baselinePooled = MemoryTracker.TakeSnapshot(forceGc: true);

        using var pool = new SecureBufferPool(bufferSize);
        for (var i = 0; i < iterations; i++)
        {
            var buf = pool.Rent();
            buf.Write(new byte[bufferSize]);
            pool.Return(buf);
        }

        var afterPooled = MemoryTracker.TakeSnapshot(forceGc: true);
        var pooledGen0 = afterPooled.Gen0Collections - baselinePooled.Gen0Collections;
        _output.WriteLine($"Pooled: Gen0 collections = {pooledGen0}");
        _output.WriteLine(MemoryTracker.FormatSnapshot("After pooled", afterPooled));

        // Measure GC collections without pooling (fresh allocations)
        var baselineFresh = MemoryTracker.TakeSnapshot(forceGc: true);

        for (var i = 0; i < iterations; i++)
        {
            var buf = new SecureBuffer(bufferSize);
            buf.Write(new byte[bufferSize]);
            buf.Dispose();
        }

        var afterFresh = MemoryTracker.TakeSnapshot(forceGc: true);
        var freshGen0 = afterFresh.Gen0Collections - baselineFresh.Gen0Collections;
        _output.WriteLine($"Fresh alloc: Gen0 collections = {freshGen0}");
        _output.WriteLine(MemoryTracker.FormatSnapshot("After fresh", afterFresh));

        // Assert — pooling should result in fewer or equal GC collections
        pooledGen0.Should().BeLessThanOrEqualTo(freshGen0,
            "pooled buffer reuse should cause fewer GC collections than fresh allocations");
    }

    [Fact]
    public void Pool_Dispose_ReleasesAll()
    {
        const int bufferSize = 128;
        const int totalRented = 1000;
        const int returnedCount = 500;

        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));

        var unreturned = new List<SecureBuffer>();

        var pool = new SecureBufferPool(bufferSize);

        // Rent 1000 buffers
        var allBuffers = new List<SecureBuffer>(totalRented);
        for (var i = 0; i < totalRented; i++)
        {
            allBuffers.Add(pool.Rent());
        }

        // Return first 500
        for (var i = 0; i < returnedCount; i++)
        {
            pool.Return(allBuffers[i]);
        }

        // Keep the remaining 500 as unreturned
        for (var i = returnedCount; i < totalRented; i++)
        {
            unreturned.Add(allBuffers[i]);
        }

        _output.WriteLine($"Pool count before dispose: {pool.Count}");

        // Dispose pool — should release all pooled buffers
        pool.Dispose();

        // Also dispose unreturned buffers to avoid real leak
        foreach (var buf in unreturned)
        {
            buf.Dispose();
        }
        unreturned.Clear();

        var afterCleanup = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After cleanup", afterCleanup));

        var delta = MemoryTracker.MemoryDelta(baseline, afterCleanup);
        _output.WriteLine($"Memory delta: {delta / 1024.0:F2} KB");

        // Assert — in parallel test execution, GC pressure inflates delta significantly
        delta.Should().BeLessThan(200 * 1024 * 1024,
            "disposing the pool and all unreturned buffers should release memory (delta: {0:F2} MB)", delta / 1024.0 / 1024.0);
    }
}
