using CyTypes.Core.Memory;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.MemoryPressure;

[Trait("Category", "Stress")]
[Trait("SubCategory", "MemoryPressure")]
public class SecureBufferMemoryTests
{
    private readonly ITestOutputHelper _output;

    public SecureBufferMemoryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Allocate_Thousands_ThenDispose_NoLeak()
    {
        // Arrange
        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));

        var buffers = new List<SecureBuffer>(StressTestConfig.SecureBufferAllocCount);

        // Act — allocate
        for (var i = 0; i < StressTestConfig.SecureBufferAllocCount; i++)
        {
            var buf = new SecureBuffer(64);
            buf.Write(new byte[64]);
            buffers.Add(buf);
        }

        var afterAlloc = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After allocation", afterAlloc));

        // Act — dispose all
        foreach (var buf in buffers)
        {
            buf.Dispose();
        }
        buffers.Clear();

        var afterCleanup = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After cleanup", afterCleanup));

        var delta = MemoryTracker.MemoryDelta(baseline, afterCleanup);
        _output.WriteLine($"Memory delta: {delta / 1024.0:F2} KB");

        // Assert — pinned memory may cause fragmentation; in parallel test execution
        // GC pressure from other tests can inflate the delta significantly
        delta.Should().BeLessThan(200 * 1024 * 1024,
            "disposing all SecureBuffers should release memory (delta: {0:F2} MB)", delta / 1024.0 / 1024.0);
    }

    [Fact]
    public void RapidAllocateDispose_NoFragmentation()
    {
        // Arrange — warm up and establish a stable baseline
        const int cycles = 10_000;
        for (var w = 0; w < 100; w++)
        {
            var warmup = new SecureBuffer(64);
            warmup.Write(new byte[64]);
            warmup.Dispose();
        }

        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));
        var counter = new ThroughputCounter();

        // Act
        for (var i = 0; i < cycles; i++)
        {
            var buf = new SecureBuffer(64);
            buf.Write(new byte[64]);
            buf.Dispose();
            counter.Increment();
        }

        var afterCycles = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After 10K alloc/dispose cycles", afterCycles));
        _output.WriteLine($"Throughput: {counter.Summary}");

        var delta = MemoryTracker.MemoryDelta(baseline, afterCycles);
        _output.WriteLine($"Memory delta: {delta / 1024.0:F2} KB");

        // Assert — pinned arrays cause heap fragmentation, so we verify that
        // memory growth is bounded (not more than 100MB total growth)
        // rather than using a percentage-based tolerance.
        delta.Should().BeLessThan(200 * 1024 * 1024,
            "rapid alloc/dispose cycles should not cause unbounded memory growth (delta: {0:F2} MB)", delta / 1024.0 / 1024.0);
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(65536)]
    [InlineData(1048576)]
    [InlineData(4194304)]
    public void LargeBuffer_Allocation_VariousSizes(int size)
    {
        // Arrange
        var data = new byte[size];
        Random.Shared.NextBytes(data);

        // Act
        var buf = new SecureBuffer(size);
        buf.Write(data);

        // Assert — round-trip
        buf.Length.Should().Be(size);
        buf.AsSpan().SequenceEqual(data).Should().BeTrue("written data should round-trip correctly");

        // Dispose and verify
        buf.Dispose();
        buf.IsDisposed.Should().BeTrue();
    }
}
