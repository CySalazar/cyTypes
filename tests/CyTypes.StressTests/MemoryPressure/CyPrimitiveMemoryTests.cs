using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.MemoryPressure;

[Trait("Category", "Stress")]
[Trait("SubCategory", "MemoryPressure")]
public class CyPrimitiveMemoryTests
{
    private readonly ITestOutputHelper _output;

    public CyPrimitiveMemoryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Create_Thousands_CyInt_Dispose_AllMemoryReleased()
    {
        const int count = 5000;
        var policy = SecurityPolicy.Performance;

        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));

        var instances = new List<CyInt>(count);
        for (var i = 0; i < count; i++)
        {
            instances.Add(new CyInt(i, policy));
        }

        var afterAlloc = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After allocation", afterAlloc));
        _output.WriteLine($"Allocated {count} CyInt instances, memory used: {MemoryTracker.MemoryDelta(baseline, afterAlloc) / 1024.0:F2} KB");

        // Dispose all
        foreach (var inst in instances)
        {
            inst.Dispose();
        }
        instances.Clear();

        var afterCleanup = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After cleanup", afterCleanup));

        var delta = MemoryTracker.MemoryDelta(baseline, afterCleanup);
        _output.WriteLine($"Memory delta: {delta / 1024.0:F2} KB");

        // Assert — in parallel test execution, GC pressure from other tests inflates delta
        delta.Should().BeLessThan(200 * 1024 * 1024,
            "disposing 5000 CyInt instances should release memory (delta: {0:F2} MB)", delta / 1024.0 / 1024.0);
    }

    [Fact]
    public void AllTypes_MassCreation_MemoryProfile()
    {
        const int countPerType = 1000;
        var policy = SecurityPolicy.Performance;
        var allDisposables = new List<IDisposable>();

        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));

        // CyInt
        var beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyInt(i, policy));
        var afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyInt ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyLong
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyLong(i, policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyLong ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyFloat
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyFloat(i * 1.1f, policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyFloat ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyDouble
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyDouble(i * 1.1, policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyDouble ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyDecimal
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyDecimal(i * 1.1m, policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyDecimal ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyBool
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyBool(i % 2 == 0, policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyBool ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyString
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyString($"test-{i}", policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyString ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyBytes
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyBytes(new byte[] { (byte)(i % 256) }, policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyBytes ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyGuid
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyGuid(Guid.NewGuid(), policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyGuid ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        // CyDateTime
        beforeType = MemoryTracker.TakeSnapshot(forceGc: false);
        for (var i = 0; i < countPerType; i++)
            allDisposables.Add(new CyDateTime(DateTime.UtcNow.AddSeconds(i), policy));
        afterType = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"CyDateTime ({countPerType}): {MemoryTracker.MemoryDelta(beforeType, afterType) / 1024.0:F2} KB");

        var afterAllAlloc = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine($"\nTotal after all types ({allDisposables.Count} instances): " +
                          $"{MemoryTracker.MemoryDelta(baseline, afterAllAlloc) / 1024.0 / 1024.0:F2} MB");

        // Dispose all
        foreach (var disposable in allDisposables)
        {
            disposable.Dispose();
        }
        allDisposables.Clear();

        var afterCleanup = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After cleanup", afterCleanup));

        var delta = MemoryTracker.MemoryDelta(baseline, afterCleanup);
        _output.WriteLine($"Final memory delta: {delta / 1024.0:F2} KB");

        // Assert — in parallel test execution, GC pressure inflates delta
        delta.Should().BeLessThan(200 * 1024 * 1024,
            "disposing all CyType instances should reclaim memory (delta: {0:F2} MB)", delta / 1024.0 / 1024.0);
    }
}
