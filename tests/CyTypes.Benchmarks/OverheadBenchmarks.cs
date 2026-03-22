using System.Diagnostics.CodeAnalysis;
using BenchmarkDotNet.Attributes;
using CyTypes.Core.Policy;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
[SuppressMessage("Reliability", "CA1001:Types that own disposable fields should be disposable")]
public class OverheadBenchmarks
{
    private CyInt _cyA = null!;
    private CyInt _cyB = null!;
    private CyString _cyStrA = null!;
    private CyString _cyStrB = null!;
    private CyBytes _cyBytesA = null!;

    [GlobalSetup]
    public void Setup()
    {
        _cyA = new CyInt(42, SecurityPolicy.Performance);
        _cyB = new CyInt(17, SecurityPolicy.Performance);
        _cyStrA = new CyString("Hello", SecurityPolicy.Performance);
        _cyStrB = new CyString("World", SecurityPolicy.Performance);
        _cyBytesA = new CyBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, SecurityPolicy.Performance);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cyA?.Dispose();
        _cyB?.Dispose();
        _cyStrA?.Dispose();
        _cyStrB?.Dispose();
        _cyBytesA?.Dispose();
    }

    // --- CyInt vs int ---

    [Benchmark]
    public int CyInt_Add()
    {
        using var result = _cyA + _cyB;
        return result.ToInsecureInt();
    }

    [Benchmark(Baseline = true)]
    public int Native_Add() => 42 + 17;

    [Benchmark]
    public int CyInt_Multiply()
    {
        using var result = _cyA * _cyB;
        return result.ToInsecureInt();
    }

    [Benchmark]
    public int Native_Multiply() => 42 * 17;

    [Benchmark]
    public bool CyInt_Compare() => _cyA > _cyB;

    [Benchmark]
    public bool Native_Compare() => 42 > 17;

    // --- CyString vs string ---

    [Benchmark]
    public string CyString_Concat()
    {
        using var result = _cyStrA + _cyStrB;
        return result.ToInsecureString();
    }

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
        using var cy = new CyBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, SecurityPolicy.Performance);
        return cy.ToInsecureBytes();
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
