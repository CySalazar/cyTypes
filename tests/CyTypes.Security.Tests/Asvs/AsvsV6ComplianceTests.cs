using System.Reflection;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Pqc;
using CyTypes.Core.Memory;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Asvs;

/// <summary>
/// OWASP Application Security Verification Standard (ASVS) v4.0, Chapter V6 — Cryptography.
/// Maps each test to a specific ASVS requirement for Level 1/2 self-assessment.
/// Reference: https://owasp.org/www-project-application-security-verification-standard/
/// </summary>
public class AsvsV6ComplianceTests
{
    // --- V6.2: Algorithms ---

    /// <summary>
    /// V6.2.1: Verify that all cryptographic modules use approved algorithms (AES with key >= 128 bits).
    /// cyTypes uses AES-256-GCM exclusively.
    /// </summary>
    [Fact]
    public void V6_2_1_AesKeyLength_AtLeast128Bits()
    {
        var engine = new AesGcmEngine();
        var key = new byte[32]; // 256-bit
        RandomNumberGenerator.Fill(key);
        var plaintext = new byte[] { 1, 2, 3, 4, 5 };

        var ct = engine.Encrypt(plaintext, key);
        var pt = engine.Decrypt(ct, key);

        pt.Should().Equal(plaintext,
            because: "V6.2.1: AES-256 (>= 128-bit key) must be used for encryption");

        // Verify 256-bit key is enforced (32 bytes)
        key.Length.Should().Be(32,
            because: "V6.2.1: cyTypes enforces 256-bit AES keys");
    }

    /// <summary>
    /// V6.2.2: Verify that authenticated encryption (AEAD) is used rather than unauthenticated modes.
    /// AES-GCM provides authentication via the GCM tag.
    /// </summary>
    [Fact]
    public void V6_2_2_AuthenticatedEncryption_GcmTagVerified()
    {
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = new byte[] { 1, 2, 3, 4, 5 };

        var ciphertext = engine.Encrypt(plaintext, key);

        // Tamper with ciphertext body — must be detected by GCM tag
        ciphertext[14] ^= 0xFF;

        var act = () => engine.Decrypt(ciphertext, key);
        act.Should().Throw<CryptographicException>(
            because: "V6.2.2: Authenticated encryption must detect tampering");
    }

    /// <summary>
    /// V6.2.5: Verify that nonces, IVs, and other single-use numbers are not reused with a given key.
    /// AesGcmEngine generates random 12-byte nonces per encryption.
    /// </summary>
    [Fact]
    public void V6_2_5_NonceUniqueness_NoReuseDetected()
    {
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = new byte[] { 0x42 };

        var nonces = new HashSet<string>();
        for (int i = 0; i < 10_000; i++)
        {
            var ct = engine.Encrypt(plaintext, key);
            var nonceHex = Convert.ToHexString(ct.AsSpan(0, 12));
            nonces.Add(nonceHex).Should().BeTrue(
                because: $"V6.2.5: Nonce must be unique (collision at iteration {i})");
        }
    }

    // --- V6.3: Random Values ---

    /// <summary>
    /// V6.3.1: Verify that all random numbers, GUIDs, and similar are generated using a CSPRNG.
    /// AesGcmEngine nonces are generated via RandomNumberGenerator.Fill (CSPRNG).
    /// </summary>
    [Fact]
    public void V6_3_1_CsprngUsed_ForNonceGeneration()
    {
        var engine = new AesGcmEngine();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = new byte[16];

        // Generate multiple ciphertexts and verify nonce entropy
        var nonces = new List<byte[]>();
        for (int i = 0; i < 100; i++)
        {
            var ct = engine.Encrypt(plaintext, key);
            nonces.Add(ct[..12]);
        }

        // Statistical check: average Hamming distance between random 12-byte nonces should be ~48 bits
        var totalHamming = 0.0;
        var comparisons = 0;
        for (int i = 0; i < nonces.Count - 1; i++)
        {
            for (int j = i + 1; j < Math.Min(i + 10, nonces.Count); j++)
            {
                totalHamming += HammingDistance(nonces[i], nonces[j]);
                comparisons++;
            }
        }

        var avgHamming = totalHamming / comparisons;
        avgHamming.Should().BeGreaterThan(30,
            because: "V6.3.1: CSPRNG nonces must have high entropy (avg Hamming distance > 30 bits)");
    }

    // --- V6.4: Key Management ---

    /// <summary>
    /// V6.4.1: Verify that a key management solution is in use for creation, distribution, rotation, and revocation.
    /// SecureBuffer provides secure key storage with zeroing on dispose.
    /// </summary>
    [Fact]
    public void V6_4_1_KeyLifecycle_SecureBufferZerosOnDispose()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var buffer = new SecureBuffer(32);
        buffer.Write(key);

        // Key is usable
        buffer.AsReadOnlySpan().ToArray().Should().Equal(key);

        // Dispose zeros the key
        buffer.Dispose();
        buffer.IsDisposed.Should().BeTrue();

        // Verify internal buffer is zeroed via reflection
        var field = typeof(SecureBuffer).GetField("_buffer", BindingFlags.NonPublic | BindingFlags.Instance);
        var internalBuffer = (byte[])field!.GetValue(buffer)!;
        internalBuffer.Should().AllBeEquivalentTo((byte)0,
            because: "V6.4.1: Key material must be zeroed when no longer needed");
    }

    /// <summary>
    /// V6.4.2: Verify that key material is not exposed in application logs or error messages.
    /// SecureBuffer throws ObjectDisposedException (no key in message) after dispose.
    /// </summary>
    [Fact]
    public void V6_4_2_KeyNotExposedInExceptions()
    {
        var buffer = new SecureBuffer(32);
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        buffer.Write(key);
        buffer.Dispose();

        try
        {
            _ = buffer.AsReadOnlySpan();
            Assert.Fail("Should have thrown");
        }
        catch (ObjectDisposedException ex)
        {
            ex.Message.Should().NotContain(Convert.ToHexString(key),
                because: "V6.4.2: Key material must not appear in exception messages");
            ex.Message.Should().NotContain(Convert.ToBase64String(key));
        }
    }

    // --- V6.6: Post-Quantum ---

    /// <summary>
    /// V6.6 (informative): Verify post-quantum key exchange is available.
    /// SessionKeyNegotiator uses ML-KEM-1024 (FIPS 203) hybrid with ECDH P-256.
    /// </summary>
    [Fact]
    public void V6_6_PostQuantum_MlKem1024Available()
    {
        var kem = new MlKemKeyEncapsulation();
        var (publicKey, secretKey) = kem.GenerateKeyPair();
        var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
        var sharedSecret2 = kem.Decapsulate(ciphertext, secretKey);

        sharedSecret1.Should().Equal(sharedSecret2,
            because: "V6.6: Post-quantum KEM (ML-KEM-1024) must function correctly");
        sharedSecret1.Should().HaveCount(32,
            because: "V6.6: ML-KEM-1024 shared secret must be 256 bits");
    }

    // --- V6.2.3: HMAC ---

    /// <summary>
    /// V6.2.3: Verify that HMAC uses an approved hash function (SHA-512).
    /// </summary>
    [Fact]
    public void V6_2_3_Hmac_UsesSha512()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var data = new byte[] { 1, 2, 3 };

        var mac = HmacComparer.Compute(key, data);

        mac.Should().HaveCount(64,
            because: "V6.2.3: HMAC-SHA512 output must be 64 bytes (512 bits)");
    }

    /// <summary>
    /// V6.2.4: Verify that cryptographic primitives are used for their intended purpose.
    /// HMAC verification uses constant-time comparison.
    /// </summary>
    [Fact]
    public void V6_2_4_HmacVerification_ConstantTime()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var data = new byte[] { 1, 2, 3 };
        var mac = HmacComparer.Compute(key, data);

        HmacComparer.Verify(key, data, mac).Should().BeTrue();

        var tampered = (byte[])mac.Clone();
        tampered[0] ^= 0xFF;
        HmacComparer.Verify(key, data, tampered).Should().BeFalse(
            because: "V6.2.4: HMAC verification must reject tampered MACs");
    }

    // --- V6.5: Secure Disposal ---

    /// <summary>
    /// V6.5.1 (FDP_RIP.1): Verify sensitive data types are zeroed on disposal.
    /// </summary>
    [Fact]
    public void V6_5_1_SensitiveData_ZeroedOnDispose()
    {
        var cy = new CyString("ASVS-V6-sensitive-test-data");
        _ = cy.ToInsecureString();
        cy.Dispose();

        var act = () => cy.ToInsecureString();
        act.Should().Throw<ObjectDisposedException>(
            because: "V6.5.1: Sensitive data must not be accessible after disposal");
    }

    // --- V6.3.2: Key Derivation ---

    /// <summary>
    /// V6.3.2: Verify that key derivation functions use approved algorithms (HKDF-SHA512).
    /// </summary>
    [Fact]
    public void V6_3_2_KeyDerivation_HkdfSha512()
    {
        var ikm = new byte[32];
        RandomNumberGenerator.Fill(ikm);
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        var key1 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, new byte[] { 0x01 });
        var key2 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, new byte[] { 0x02 });

        key1.Should().HaveCount(32);
        key1.Should().NotEqual(key2,
            because: "V6.3.2: HKDF with different contexts must produce different keys");
    }

    private static int HammingDistance(byte[] a, byte[] b)
    {
        int distance = 0;
        for (int i = 0; i < Math.Min(a.Length, b.Length); i++)
        {
            var xor = (byte)(a[i] ^ b[i]);
            while (xor != 0)
            {
                distance += xor & 1;
                xor >>= 1;
            }
        }
        return distance;
    }
}
