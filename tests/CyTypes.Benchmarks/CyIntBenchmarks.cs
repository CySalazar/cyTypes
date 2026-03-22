using BenchmarkDotNet.Attributes;
using CyTypes.Core.Policy;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA1001:Types that own disposable fields should be disposable")]
public class CyIntBenchmarks
{
    private CyInt _a = null!;
    private CyInt _b = null!;

    [GlobalSetup]
    public void Setup()
    {
        _a = new CyInt(42, SecurityPolicy.Performance);
        _b = new CyInt(17, SecurityPolicy.Performance);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _a?.Dispose();
        _b?.Dispose();
    }

    [Benchmark]
    public int Add()
    {
        using var result = _a + _b;
        return result.ToInsecureInt();
    }

    [Benchmark]
    public int Multiply()
    {
        using var result = _a * _b;
        return result.ToInsecureInt();
    }

    [Benchmark]
    public int Roundtrip()
    {
        using var cy = new CyInt(123, SecurityPolicy.Performance);
        return cy.ToInsecureInt();
    }

    [Benchmark(Baseline = true)]
    public int NativeAdd() => 42 + 17;
}

