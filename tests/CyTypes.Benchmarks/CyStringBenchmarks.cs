using BenchmarkDotNet.Attributes;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class CyStringBenchmarks : IDisposable
{
    private CyString _a = null!;
    private CyString _b = null!;
    private CyString _csv = null!;
    private CyString _compareTarget = null!;

    [GlobalSetup]
    public void Setup()
    {
        _a = new CyString("Hello, ");
        _b = new CyString("World!");
        _csv = new CyString("alpha,bravo,charlie,delta,echo");
        _compareTarget = new CyString("Hello, ");
    }

    [GlobalCleanup]
    public void Cleanup() => Dispose();

    public void Dispose()
    {
        _a?.Dispose();
        _b?.Dispose();
        _csv?.Dispose();
        _compareTarget?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Benchmark]
    public CyString Concat() => _a + _b;

    [Benchmark]
    public CyString[] Split() => _csv.Split(',');

    [Benchmark]
    public CyString Roundtrip()
    {
        var cy = new CyString("benchmark test string");
        _ = cy.ToInsecureString();
        return cy;
    }

    [Benchmark]
    public bool SecureEquals() => _a.SecureEquals(_compareTarget);
}
