using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using CyTypes.Core.Crypto;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class HkdfBenchmarks
{
    private byte[] _ikm = null!;
    private byte[] _salt = null!;
    private byte[] _info = null!;

    [Params(16, 32, 64)]
    public int OutputLength { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _ikm = new byte[32];
        RandomNumberGenerator.Fill(_ikm);
        _salt = new byte[16];
        RandomNumberGenerator.Fill(_salt);
        _info = new byte[8];
        RandomNumberGenerator.Fill(_info);
    }

    [Benchmark]
    public byte[] DeriveKeyWithSaltAndInfo() =>
        HkdfKeyDerivation.DeriveKey(_ikm, OutputLength, _salt, _info);

    [Benchmark]
    public byte[] DeriveKeyNoSalt() =>
        HkdfKeyDerivation.DeriveKey(_ikm, OutputLength);

    [Benchmark(Baseline = true)]
    public byte[] BaselineHkdfDirect() =>
        HKDF.DeriveKey(HashAlgorithmName.SHA512, _ikm, OutputLength, _salt, _info);
}
