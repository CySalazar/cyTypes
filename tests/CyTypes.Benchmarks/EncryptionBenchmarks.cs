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

    [GlobalSetup]
    public void Setup()
    {
        _engine = new AesGcmEngine();
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
        _plaintext = BitConverter.GetBytes(42);
        _ciphertext = _engine.Encrypt(_plaintext, _key);
    }

    [Benchmark]
    public byte[] AesGcmEncrypt() => _engine.Encrypt(_plaintext, _key);

    [Benchmark]
    public byte[] AesGcmDecrypt() => _engine.Decrypt(_ciphertext, _key);

    [Benchmark]
    public static CyInt CyIntCreate() => new CyInt(42);
}
