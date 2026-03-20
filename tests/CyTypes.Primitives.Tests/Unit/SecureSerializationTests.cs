using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class SecureSerializationTests
{
    // Envelope layout: [version:1] [keyId:16] [nonce:12] [ciphertext:N] [HMAC-SHA512:64]
    private const int MinimumEnvelopeOverhead = 1 + 16 + 12 + 64; // 93 bytes without ciphertext

    [Fact]
    public void ToSecureBytes_produces_non_empty_output()
    {
        using var cy = new CyInt(42);

        var bytes = cy.ToSecureBytes();

        bytes.Should().NotBeEmpty();
    }

    [Fact]
    public void ToSecureBytes_has_expected_minimum_length()
    {
        using var cy = new CyInt(42);

        var bytes = cy.ToSecureBytes();

        // Must be at least the overhead (version + keyId + nonce + HMAC) plus at least 1 byte of ciphertext
        bytes.Length.Should().BeGreaterThanOrEqualTo(MinimumEnvelopeOverhead + 1);
    }

    [Fact]
    public void ToSecureBytes_envelope_starts_with_version_byte_1()
    {
        using var cy = new CyInt(42);

        var bytes = cy.ToSecureBytes();

        bytes[0].Should().Be(1, "version byte should be 1");
    }

    [Fact]
    public void ToSecureBytes_different_instances_produce_different_output()
    {
        using var a = new CyInt(42);
        using var b = new CyInt(42);

        var bytesA = a.ToSecureBytes();
        var bytesB = b.ToSecureBytes();

        // Different keys and nonces mean different output even for the same value
        bytesA.Should().NotEqual(bytesB);
    }

    [Fact]
    public void ToSecureBytes_works_for_CyString()
    {
        using var cy = new CyString("hello");

        var bytes = cy.ToSecureBytes();

        bytes.Length.Should().BeGreaterThanOrEqualTo(MinimumEnvelopeOverhead + 1);
    }

    [Fact]
    public void SecureSerializationFormat_Serialize_Deserialize_round_trip()
    {
        var ciphertext = new byte[] { 1, 2, 3, 4, 5 };
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(hmacKey);

        var envelope = CyTypes.Core.Crypto.SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);
        var (extractedKeyId, extractedCiphertext) = CyTypes.Core.Crypto.SecureSerializationFormat.Deserialize(envelope, hmacKey);

        extractedKeyId.Should().Be(keyId);
        extractedCiphertext.Should().Equal(ciphertext);
    }

    [Fact]
    public void SecureSerializationFormat_Deserialize_detects_tampering()
    {
        var ciphertext = new byte[] { 10, 20, 30 };
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(hmacKey);

        var envelope = CyTypes.Core.Crypto.SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);

        // Tamper with ciphertext area
        envelope[30] ^= 0xFF;

        var act = () => CyTypes.Core.Crypto.SecureSerializationFormat.Deserialize(envelope, hmacKey);
        act.Should().Throw<System.Security.SecurityException>();
    }

    [Fact]
    public void SecureSerializationFormat_Deserialize_rejects_wrong_version()
    {
        var ciphertext = new byte[] { 1, 2, 3 };
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(hmacKey);

        var envelope = CyTypes.Core.Crypto.SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);
        envelope[0] = 99; // wrong version

        var act = () => CyTypes.Core.Crypto.SecureSerializationFormat.Deserialize(envelope, hmacKey);
        act.Should().Throw<ArgumentException>().WithMessage("*version*");
    }

    [Fact]
    public void SecureSerializationFormat_Deserialize_rejects_too_small_envelope()
    {
        var hmacKey = new byte[32];
        var tooSmall = new byte[10];

        var act = () => CyTypes.Core.Crypto.SecureSerializationFormat.Deserialize(tooSmall, hmacKey);
        act.Should().Throw<ArgumentException>().WithMessage("*too small*");
    }

    [Fact]
    public void SecureSerializationFormat_VerifySecureBytes_returns_true_for_valid()
    {
        var ciphertext = new byte[] { 5, 6, 7 };
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(hmacKey);

        var envelope = CyTypes.Core.Crypto.SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);

        CyTypes.Core.Crypto.SecureSerializationFormat.VerifySecureBytes(envelope, hmacKey).Should().BeTrue();
    }

    [Fact]
    public void SecureSerializationFormat_VerifySecureBytes_returns_false_for_tampered()
    {
        var ciphertext = new byte[] { 5, 6, 7 };
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(hmacKey);

        var envelope = CyTypes.Core.Crypto.SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);
        envelope[30] ^= 0xFF;

        CyTypes.Core.Crypto.SecureSerializationFormat.VerifySecureBytes(envelope, hmacKey).Should().BeFalse();
    }
}
