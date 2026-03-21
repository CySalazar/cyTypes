using CyTypes.Core.Crypto.Pqc;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Nist;

/// <summary>
/// FIPS 203 (ML-KEM) validation tests for ML-KEM-1024.
/// Reference: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard).
/// Validates key generation, encapsulation, decapsulation, and security properties.
/// Note: Full KAT validation requires NIST ACVP vectors; these tests validate
/// functional correctness and cryptographic properties per FIPS 203 Section 7.
/// </summary>
public class MlKemFips203Tests
{
    [Fact]
    public void MlKem1024_KeyGeneration_ProducesValidKeyPair()
    {
        var kem = new MlKemKeyEncapsulation();

        var (publicKey, secretKey) = kem.GenerateKeyPair();

        publicKey.Should().NotBeEmpty("ML-KEM-1024 public key must not be empty");
        secretKey.Should().NotBeEmpty("ML-KEM-1024 secret key must not be empty");

        // ML-KEM-1024 public key (DER-encoded SubjectPublicKeyInfo) should be > 1568 bytes
        publicKey.Length.Should().BeGreaterThan(1500,
            because: "ML-KEM-1024 public key (DER) should be substantial");

        // Secret key should be larger than public key
        secretKey.Length.Should().BeGreaterThan(publicKey.Length,
            because: "ML-KEM-1024 secret key contains additional material");
    }

    [Fact]
    public void MlKem1024_EncapsulateDecapsulate_SharedSecretsMatch()
    {
        var kem = new MlKemKeyEncapsulation();
        var (publicKey, secretKey) = kem.GenerateKeyPair();

        var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
        var sharedSecret2 = kem.Decapsulate(ciphertext, secretKey);

        sharedSecret1.Should().Equal(sharedSecret2,
            because: "FIPS 203: Decaps(Encaps(pk), sk) must yield identical shared secret");
    }

    [Fact]
    public void MlKem1024_SharedSecret_Is32Bytes()
    {
        var kem = new MlKemKeyEncapsulation();
        var (publicKey, secretKey) = kem.GenerateKeyPair();

        var (_, sharedSecret) = kem.Encapsulate(publicKey);

        sharedSecret.Should().HaveCount(32,
            because: "FIPS 203: ML-KEM shared secret must be 256 bits (32 bytes)");
    }

    [Fact]
    public void MlKem1024_DifferentEncapsulations_ProduceDifferentCiphertexts()
    {
        var kem = new MlKemKeyEncapsulation();
        var (publicKey, _) = kem.GenerateKeyPair();

        var (ct1, _) = kem.Encapsulate(publicKey);
        var (ct2, _) = kem.Encapsulate(publicKey);

        ct1.Should().NotEqual(ct2,
            because: "FIPS 203: Each encapsulation must use fresh randomness");
    }

    [Fact]
    public void MlKem1024_DifferentKeyPairs_ProduceDifferentSharedSecrets()
    {
        var kem = new MlKemKeyEncapsulation();
        var (pub1, _) = kem.GenerateKeyPair();
        var (pub2, _) = kem.GenerateKeyPair();

        var (_, ss1) = kem.Encapsulate(pub1);
        var (_, ss2) = kem.Encapsulate(pub2);

        ss1.Should().NotEqual(ss2,
            because: "Different key pairs must produce different shared secrets");
    }

    [Fact]
    public void MlKem1024_WrongSecretKey_ProducesDifferentSharedSecret()
    {
        var kem = new MlKemKeyEncapsulation();
        var (publicKey, _) = kem.GenerateKeyPair();
        var (_, wrongSecretKey) = kem.GenerateKeyPair();

        var (ciphertext, correctShared) = kem.Encapsulate(publicKey);

        // Decapsulating with wrong key should produce a different (implicit rejection) value
        var wrongShared = kem.Decapsulate(ciphertext, wrongSecretKey);

        wrongShared.Should().NotEqual(correctShared,
            because: "FIPS 203: Decapsulation with wrong secret key must not reveal the correct shared secret");
    }

    [Fact]
    public void MlKem1024_MultipleRoundtrips_AllSucceed()
    {
        var kem = new MlKemKeyEncapsulation();

        for (int i = 0; i < 10; i++)
        {
            var (publicKey, secretKey) = kem.GenerateKeyPair();
            var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
            var sharedSecret2 = kem.Decapsulate(ciphertext, secretKey);

            sharedSecret1.Should().Equal(sharedSecret2,
                because: $"FIPS 203 roundtrip {i} must succeed");
        }
    }

    [Fact]
    public void MlKem1024_CiphertextSize_IsConsistent()
    {
        var kem = new MlKemKeyEncapsulation();
        var (publicKey, _) = kem.GenerateKeyPair();

        var sizes = new HashSet<int>();
        for (int i = 0; i < 5; i++)
        {
            var (ciphertext, _) = kem.Encapsulate(publicKey);
            sizes.Add(ciphertext.Length);
        }

        sizes.Should().HaveCount(1,
            because: "ML-KEM-1024 ciphertext size must be constant across encapsulations");
    }

    [Fact]
    public void MlKem1024_NullPublicKey_Throws()
    {
        var kem = new MlKemKeyEncapsulation();

        var act = () => kem.Encapsulate(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void MlKem1024_NullCiphertext_Throws()
    {
        var kem = new MlKemKeyEncapsulation();
        var (_, secretKey) = kem.GenerateKeyPair();

        var act = () => kem.Decapsulate(null!, secretKey);

        act.Should().Throw<ArgumentNullException>();
    }
}
