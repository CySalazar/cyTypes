using BenchmarkDotNet.Attributes;
using CyTypes.Core.Crypto.KeyExchange;
using CyTypes.Core.Crypto.Pqc;

namespace CyTypes.Benchmarks;

/// <summary>
/// Benchmarks for post-quantum cryptography operations (ML-KEM-1024)
/// and hybrid ECDH P-256 + ML-KEM key exchange.
/// </summary>
[MemoryDiagnoser]
public class PqcBenchmarks
{
    private MlKemKeyEncapsulation _kem = null!;
    private byte[] _publicKey = null!;
    private byte[] _secretKey = null!;
    private byte[] _ciphertext = null!;

    [GlobalSetup]
    public void Setup()
    {
        _kem = new MlKemKeyEncapsulation();
        (_publicKey, _secretKey) = _kem.GenerateKeyPair();
        (_ciphertext, _) = _kem.Encapsulate(_publicKey);
    }

    [Benchmark(Description = "ML-KEM-1024 GenerateKeyPair")]
    public (byte[], byte[]) MlKemGenerateKeyPair() => _kem.GenerateKeyPair();

    [Benchmark(Description = "ML-KEM-1024 Encapsulate")]
    public (byte[], byte[]) MlKemEncapsulate() => _kem.Encapsulate(_publicKey);

    [Benchmark(Description = "ML-KEM-1024 Decapsulate")]
    public byte[] MlKemDecapsulate() => _kem.Decapsulate(_ciphertext, _secretKey);

    [Benchmark(Description = "Hybrid Handshake (ECDH P-256 + ML-KEM-1024)")]
    public void HybridHandshake()
    {
        using var initiator = new SessionKeyNegotiator();
        using var responder = new SessionKeyNegotiator();

        var initiatorHandshake = initiator.CreateHandshake();
        var responderHandshake = responder.CreateHandshake();

        var (sessionKeyI, mlKemCiphertext) = initiator.DeriveSessionKeyAsInitiator(responderHandshake);
        var sessionKeyR = responder.DeriveSessionKeyAsResponder(initiatorHandshake, mlKemCiphertext);

        sessionKeyI.Dispose();
        sessionKeyR.Dispose();
    }
}
