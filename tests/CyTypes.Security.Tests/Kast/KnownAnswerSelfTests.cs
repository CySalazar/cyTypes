using System.Security.Cryptography;
using System.Text;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Kast;

/// <summary>
/// Known Answer Self-Tests (KAT) for FIPS 140-3 Level 1 alignment.
/// All expected values are precomputed with the .NET reference implementation
/// and hardcoded to detect regressions or implementation changes.
/// </summary>
public class KnownAnswerSelfTests
{
    // AES-256-GCM KAT constants
    private const string KatAesKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string KatAesNonce = "000102030405060708090a0b";
    private const string KatAesPlaintext = "KAT-AES-256-GCM";
    private const string KatAesCiphertext = "0C43823684A09136BF74A1A6F6AA35";
    private const string KatAesTag = "0F786157D523F14A861987364F71D69D";

    // HKDF-SHA512 KAT constants
    private const string KatHkdfIkm = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string KatHkdfSalt = "KAT-HKDF-SHA512";
    private const string KatHkdfInfo = "KAT-INFO";
    private const string KatHkdfOkm = "285A53C16CE1B94E5701A6E0C81F7EE045C1CCF9190911296E92E88615569DD6";

    // HMAC-SHA512 KAT constants
    private const string KatHmacKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string KatHmacData = "KAT-HMAC-SHA512";
    private const string KatHmacExpected = "8C5F22E705418C670079802618D1891899CF3FD5864F8EAFABFE68EE8D33431DB622E636EF2486C9E4ADD42786ECF926AB2FC42B86899D1C34979715607856BA";

    [Fact]
    public void Kat_AesGcm_Decrypt_MatchesExpected()
    {
        var engine = new AesGcmEngine();
        var key = Convert.FromHexString(KatAesKey);
        var nonce = Convert.FromHexString(KatAesNonce);
        var ct = Convert.FromHexString(KatAesCiphertext);
        var tag = Convert.FromHexString(KatAesTag);

        // Reconstruct engine format: [nonce:12][ct:N][tag:16]
        var engineCt = new byte[nonce.Length + ct.Length + tag.Length];
        nonce.CopyTo(engineCt, 0);
        ct.CopyTo(engineCt, nonce.Length);
        tag.CopyTo(engineCt, nonce.Length + ct.Length);

        var plaintext = engine.Decrypt(engineCt, key);

        Encoding.UTF8.GetString(plaintext).Should().Be(KatAesPlaintext);
    }

    [Fact]
    public void Kat_AesGcm_Encrypt_ProducesValidCiphertext()
    {
        // We can't verify exact ciphertext (random nonce), but we verify roundtrip
        var engine = new AesGcmEngine();
        var key = Convert.FromHexString(KatAesKey);
        var plaintext = Encoding.UTF8.GetBytes(KatAesPlaintext);

        var ciphertext = engine.Encrypt(plaintext, key);
        var decrypted = engine.Decrypt(ciphertext, key);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void Kat_HkdfSha512_MatchesExpected()
    {
        var ikm = Convert.FromHexString(KatHkdfIkm);
        var salt = Encoding.UTF8.GetBytes(KatHkdfSalt);
        var info = Encoding.UTF8.GetBytes(KatHkdfInfo);

        var okm = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, info);

        Convert.ToHexString(okm).Should().BeEquivalentTo(KatHkdfOkm);
    }

    [Fact]
    public void Kat_HmacSha512_MatchesExpected()
    {
        var key = Convert.FromHexString(KatHmacKey);
        var data = Encoding.UTF8.GetBytes(KatHmacData);

        var mac = HmacComparer.Compute(key, data);

        Convert.ToHexString(mac).Should().BeEquivalentTo(KatHmacExpected);
    }

    [Fact]
    public void Kat_HmacSha512_VerifySucceeds()
    {
        var key = Convert.FromHexString(KatHmacKey);
        var data = Encoding.UTF8.GetBytes(KatHmacData);
        var expectedMac = Convert.FromHexString(KatHmacExpected);

        HmacComparer.Verify(key, data, expectedMac).Should().BeTrue();
    }

    [Fact]
    public void Kat_AllSelfTests_PassOnStartup()
    {
        // Meta-test: ensures all KAT tests can run as a self-test battery
        Kat_AesGcm_Decrypt_MatchesExpected();
        Kat_AesGcm_Encrypt_ProducesValidCiphertext();
        Kat_HkdfSha512_MatchesExpected();
        Kat_HmacSha512_MatchesExpected();
        Kat_HmacSha512_VerifySucceeds();
    }
}
