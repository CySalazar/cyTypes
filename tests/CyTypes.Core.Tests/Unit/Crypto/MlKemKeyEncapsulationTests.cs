using CyTypes.Core.Crypto.Pqc;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class MlKemKeyEncapsulationTests
{
    private readonly MlKemKeyEncapsulation _kem = new();

    [Fact]
    public void GenerateKeyPair_produces_non_empty_keys()
    {
        var (publicKey, secretKey) = _kem.GenerateKeyPair();

        publicKey.Should().NotBeEmpty();
        secretKey.Should().NotBeEmpty();
    }

    [Fact]
    public void Encapsulate_Decapsulate_shared_secrets_match()
    {
        var (publicKey, secretKey) = _kem.GenerateKeyPair();
        var (ciphertext, sharedSecret) = _kem.Encapsulate(publicKey);

        var decapsulatedSecret = _kem.Decapsulate(ciphertext, secretKey);

        decapsulatedSecret.Should().Equal(sharedSecret);
    }

    [Fact]
    public void SharedSecret_is_32_bytes()
    {
        var (publicKey, _) = _kem.GenerateKeyPair();
        var (_, sharedSecret) = _kem.Encapsulate(publicKey);

        sharedSecret.Should().HaveCount(32);
    }

    [Fact]
    public void Different_keypairs_produce_different_secrets()
    {
        var (pk1, sk1) = _kem.GenerateKeyPair();
        var (pk2, _) = _kem.GenerateKeyPair();

        var (ct1, secret1) = _kem.Encapsulate(pk1);
        var (ct2, secret2) = _kem.Encapsulate(pk2);

        secret1.Should().NotEqual(secret2);
    }

    [Fact]
    public void MlKemKeyPair_Dispose_zeros_key_material()
    {
        var (publicKey, secretKey) = _kem.GenerateKeyPair();
        var keyPair = new MlKemKeyPair(publicKey, secretKey);

        keyPair.Dispose();

        keyPair.SecretKey.Should().AllBeEquivalentTo((byte)0);
    }
}
