using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using CyTypes.Core.Crypto;
using CyTypes.Primitives;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class EncryptionBenchmarks
{
    private AesGcmEngine _engine = null!;
    private byte[] _key = null!;
    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;

    [Params(16, 64, 256, 1024, 4096)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _engine = new AesGcmEngine();
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
        _plaintext = new byte[PayloadSize];
        RandomNumberGenerator.Fill(_plaintext);
        _ciphertext = _engine.Encrypt(_plaintext, _key);
    }

    [Benchmark]
    public byte[] AesGcmEncrypt() => _engine.Encrypt(_plaintext, _key);

    [Benchmark]
    public byte[] AesGcmDecrypt() => _engine.Decrypt(_ciphertext, _key);

    [Benchmark]
    public CyInt CyIntCreate() => new(42);

    [Benchmark]
    public byte[] HkdfDerive() =>
        HkdfKeyDerivation.DeriveKey(_key, 32, _plaintext.AsSpan(0, Math.Min(16, _plaintext.Length)));

    [Benchmark]
    public byte[] HmacCompute() => HmacComparer.Compute(_key, _plaintext);
}
