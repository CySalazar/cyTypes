using System.Diagnostics.CodeAnalysis;
using BenchmarkDotNet.Attributes;
using CyTypes.Core.Policy;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
[SuppressMessage("Reliability", "CA1001:Types that own disposable fields should be disposable")]
public class CyStringBenchmarks
{
    private CyString _a = null!;
    private CyString _b = null!;
    private CyString _csv = null!;
    private CyString _compareTarget = null!;

    [GlobalSetup]
    public void Setup()
    {
        _a = new CyString("Hello, ", SecurityPolicy.Performance);
        _b = new CyString("World!", SecurityPolicy.Performance);
        _csv = new CyString("alpha,bravo,charlie,delta,echo", SecurityPolicy.Performance);
        _compareTarget = new CyString("Hello, ", SecurityPolicy.Performance);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _a?.Dispose();
        _b?.Dispose();
        _csv?.Dispose();
        _compareTarget?.Dispose();
    }

    [Benchmark]
    public string Concat()
    {
        using var result = _a + _b;
        return result.ToInsecureString();
    }

    [Benchmark]
    public int Split()
    {
        var parts = _csv.Split(',');
        foreach (var part in parts)
            part.Dispose();
        return parts.Length;
    }

    [Benchmark]
    public string Roundtrip()
    {
        using var cy = new CyString("benchmark test string", SecurityPolicy.Performance);
        return cy.ToInsecureString();
    }

    [Benchmark]
    public bool SecureEquals() => _a.SecureEquals(_compareTarget);
}
