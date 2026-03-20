using BenchmarkDotNet.Attributes;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;

namespace CyTypes.Benchmarks;

/// <summary>
/// Benchmarks comparing FHE (BFV) operations vs baseline AES-GCM operations.
/// </summary>
[MemoryDiagnoser]
public class FheBenchmarks : IDisposable
{
    private SealKeyManager _keyManager = null!;
    private SealBfvEngine _fheEngine = null!;
    private ICryptoEngine _aesEngine = null!;
    private byte[] _fheCiphertextA = null!;
    private byte[] _fheCiphertextB = null!;
    private byte[] _aesCiphertextA = null!;
    private byte[] _aesCiphertextB = null!;
    private byte[] _aesKey = null!;

    [GlobalSetup]
    public void Setup()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _fheEngine = new SealBfvEngine(_keyManager);

        _fheCiphertextA = _fheEngine.Encrypt(42);
        _fheCiphertextB = _fheEngine.Encrypt(17);

        _aesEngine = new AesGcmEngine();
        _aesKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(_aesKey);
        _aesCiphertextA = _aesEngine.Encrypt(BitConverter.GetBytes(42), _aesKey);
        _aesCiphertextB = _aesEngine.Encrypt(BitConverter.GetBytes(17), _aesKey);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _fheEngine.Dispose();
        _keyManager.Dispose();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _fheEngine?.Dispose();
        _keyManager?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Benchmark(Description = "FHE BFV Encrypt")]
    public byte[] FheEncrypt() => _fheEngine.Encrypt(42);

    [Benchmark(Description = "FHE BFV Decrypt")]
    public long FheDecrypt() => _fheEngine.Decrypt(_fheCiphertextA);

    [Benchmark(Description = "FHE BFV Add")]
    public byte[] FheAdd() => _fheEngine.Add(_fheCiphertextA, _fheCiphertextB);

    [Benchmark(Description = "FHE BFV Multiply")]
    public byte[] FheMultiply() => _fheEngine.Multiply(_fheCiphertextA, _fheCiphertextB);

    [Benchmark(Baseline = true, Description = "AES-GCM Encrypt")]
    public byte[] AesEncrypt() => _aesEngine.Encrypt(BitConverter.GetBytes(42), _aesKey);

    [Benchmark(Description = "AES-GCM Decrypt")]
    public byte[] AesDecrypt() => _aesEngine.Decrypt(_aesCiphertextA, _aesKey);

    [Benchmark(Description = "AES-GCM Add (decrypt+compute+encrypt)")]
    public byte[] AesAdd()
    {
        var a = BitConverter.ToInt32(_aesEngine.Decrypt(_aesCiphertextA, _aesKey));
        var b = BitConverter.ToInt32(_aesEngine.Decrypt(_aesCiphertextB, _aesKey));
        return _aesEngine.Encrypt(BitConverter.GetBytes(a + b), _aesKey);
    }
}
