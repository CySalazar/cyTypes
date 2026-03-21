using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using CyTypes.Core.Crypto;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class HmacBenchmarks
{
    private byte[] _key = null!;
    private byte[] _data = null!;
    private byte[] _mac = null!;

    [Params(16, 64, 256, 1024)]
    public int DataSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
        _data = new byte[DataSize];
        RandomNumberGenerator.Fill(_data);
        _mac = HmacComparer.Compute(_key, _data);
    }

    [Benchmark]
    public byte[] Compute() => HmacComparer.Compute(_key, _data);

    [Benchmark]
    public bool Verify() => HmacComparer.Verify(_key, _data, _mac);

    [Benchmark(Baseline = true)]
    public byte[] BaselineHmacDirect() => HMACSHA512.HashData(_key, _data);
}
