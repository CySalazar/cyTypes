using BenchmarkDotNet.Attributes;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class OverheadBenchmarks : IDisposable
{
    private CyInt _cyA = null!;
    private CyInt _cyB = null!;
    private CyString _cyStrA = null!;
    private CyString _cyStrB = null!;
    private CyBytes _cyBytesA = null!;

    [GlobalSetup]
    public void Setup()
    {
        _cyA = new CyInt(42);
        _cyB = new CyInt(17);
        _cyStrA = new CyString("Hello");
        _cyStrB = new CyString("World");
        _cyBytesA = new CyBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
    }

    [GlobalCleanup]
    public void Cleanup() => Dispose();

    public void Dispose()
    {
        _cyA?.Dispose();
        _cyB?.Dispose();
        _cyStrA?.Dispose();
        _cyStrB?.Dispose();
        _cyBytesA?.Dispose();
        GC.SuppressFinalize(this);
    }

    // --- CyInt vs int ---

    [Benchmark]
    public CyInt CyInt_Add() => _cyA + _cyB;

    [Benchmark(Baseline = true)]
    public int Native_Add() => 42 + 17;

    [Benchmark]
    public CyInt CyInt_Multiply() => _cyA * _cyB;

    [Benchmark]
    public int Native_Multiply() => 42 * 17;

    [Benchmark]
    public bool CyInt_Compare() => _cyA > _cyB;

    [Benchmark]
    public bool Native_Compare() => 42 > 17;

    // --- CyString vs string ---

    [Benchmark]
    public CyString CyString_Concat() => _cyStrA + _cyStrB;

    [Benchmark]
    public string Native_Concat() => "Hello" + "World";

    [Benchmark]
    public int CyString_Length() => _cyStrA.Length;

    [Benchmark]
    public int Native_Length() => "Hello".Length;

    [Benchmark]
    public bool CyString_Equals() => _cyStrA.Equals(_cyStrB);

    [Benchmark]
    public bool Native_Equals() => "Hello".Equals("World", StringComparison.Ordinal);

    // --- CyBytes vs byte[] ---

    [Benchmark]
    public byte[] CyBytes_Roundtrip()
    {
        var cy = new CyBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        var result = cy.ToInsecureBytes();
        cy.Dispose();
        return result;
    }

    [Benchmark]
    public byte[] Native_BytesCopy()
    {
        var source = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var dest = new byte[source.Length];
        source.CopyTo(dest, 0);
        return dest;
    }
}
