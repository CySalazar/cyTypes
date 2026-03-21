using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using CyTypes.Core.Crypto;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class PayloadBenchmarks
{
    private AesGcmEngine _engine = null!;
    private byte[] _key = null!;
    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;
    private byte[] _aad = null!;
    private byte[] _ciphertextWithAad = null!;

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
        _aad = new byte[16];
        RandomNumberGenerator.Fill(_aad);
        _ciphertext = _engine.Encrypt(_plaintext, _key);
        _ciphertextWithAad = _engine.Encrypt(_plaintext, _key, _aad);
    }

    [Benchmark]
    public byte[] Encrypt() => _engine.Encrypt(_plaintext, _key);

    [Benchmark]
    public byte[] Decrypt() => _engine.Decrypt(_ciphertext, _key);

    [Benchmark]
    public byte[] EncryptWithAad() => _engine.Encrypt(_plaintext, _key, _aad);

    [Benchmark]
    public byte[] DecryptWithAad() => _engine.Decrypt(_ciphertextWithAad, _key, _aad);

    [Benchmark(Baseline = true)]
    public byte[] BaselineAesGcmDirect()
    {
        var output = new byte[12 + _plaintext.Length + 16];
        var nonce = output.AsSpan(0, 12);
        var ct = output.AsSpan(12, _plaintext.Length);
        var tag = output.AsSpan(12 + _plaintext.Length, 16);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, _plaintext, ct, tag);
        return output;
    }
}
