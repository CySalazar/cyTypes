using BenchmarkDotNet.Attributes;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class CyIntBenchmarks : IDisposable
{
    private CyInt _a = null!;
    private CyInt _b = null!;

    [GlobalSetup]
    public void Setup()
    {
        _a = new CyInt(42);
        _b = new CyInt(17);
    }

    [GlobalCleanup]
    public void Cleanup() => Dispose();

    public void Dispose()
    {
        _a?.Dispose();
        _b?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Benchmark]
    public CyInt Add() => _a + _b;

    [Benchmark]
    public CyInt Multiply() => _a * _b;

    [Benchmark]
    public CyInt Roundtrip()
    {
        var cy = new CyInt(123);
        _ = cy.ToInsecureInt();
        return cy;
    }

    [Benchmark(Baseline = true)]
    public int NativeAdd() => 42 + 17;
}
