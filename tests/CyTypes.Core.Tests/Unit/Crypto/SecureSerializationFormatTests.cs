using System.Security;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class SecureSerializationFormatTests
{
    private static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Serialize_Deserialize_round_trip()
    {
        var key = GenerateKey();
        var keyId = Guid.NewGuid();
        var ciphertext = new byte[] { 10, 20, 30 };

        var envelope = SecureSerializationFormat.Serialize(ciphertext, keyId, key);
        var (extractedKeyId, extractedCiphertext) = SecureSerializationFormat.Deserialize(envelope, key);

        extractedKeyId.Should().Be(keyId);
        extractedCiphertext.Should().Equal(ciphertext);
    }

    [Fact]
    public void Deserialize_too_small_envelope_throws()
    {
        var key = GenerateKey();
        var act = () => SecureSerializationFormat.Deserialize(new byte[10], key);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_wrong_version_throws()
    {
        var key = GenerateKey();
        var keyId = Guid.NewGuid();
        var envelope = SecureSerializationFormat.Serialize(new byte[] { 1 }, keyId, key);
        envelope[0] = 99;

        var act = () => SecureSerializationFormat.Deserialize(envelope, key);
        act.Should().Throw<ArgumentException>().WithMessage("*version*");
    }

    [Fact]
    public void Deserialize_tampered_envelope_throws_SecurityException()
    {
        var key = GenerateKey();
        var keyId = Guid.NewGuid();
        var envelope = SecureSerializationFormat.Serialize(new byte[] { 1, 2, 3 }, keyId, key);

        // Tamper with ciphertext area
        envelope[30] ^= 0xFF;

        var act = () => SecureSerializationFormat.Deserialize(envelope, key);
        act.Should().Throw<SecurityException>();
    }

    [Fact]
    public void VerifySecureBytes_valid_envelope_returns_true()
    {
        var key = GenerateKey();
        var envelope = SecureSerializationFormat.Serialize(new byte[] { 42 }, Guid.NewGuid(), key);

        SecureSerializationFormat.VerifySecureBytes(envelope, key).Should().BeTrue();
    }

    [Fact]
    public void VerifySecureBytes_tampered_returns_false()
    {
        var key = GenerateKey();
        var envelope = SecureSerializationFormat.Serialize(new byte[] { 42 }, Guid.NewGuid(), key);
        envelope[30] ^= 0xFF;

        SecureSerializationFormat.VerifySecureBytes(envelope, key).Should().BeFalse();
    }

    [Fact]
    public void VerifySecureBytes_too_small_returns_false()
    {
        SecureSerializationFormat.VerifySecureBytes(new byte[5], GenerateKey()).Should().BeFalse();
    }

    [Fact]
    public void VerifySecureBytes_wrong_version_returns_false()
    {
        var key = GenerateKey();
        var envelope = SecureSerializationFormat.Serialize(new byte[] { 1 }, Guid.NewGuid(), key);
        envelope[0] = 99;

        SecureSerializationFormat.VerifySecureBytes(envelope, key).Should().BeFalse();
    }

    [Fact]
    public void Serialize_empty_ciphertext_round_trips()
    {
        var key = GenerateKey();
        var keyId = Guid.NewGuid();

        var envelope = SecureSerializationFormat.Serialize(ReadOnlySpan<byte>.Empty, keyId, key);
        var (extractedKeyId, extractedCiphertext) = SecureSerializationFormat.Deserialize(envelope, key);

        extractedKeyId.Should().Be(keyId);
        extractedCiphertext.Should().BeEmpty();
    }

    [Fact]
    public void Constants_have_expected_values()
    {
        SecureSerializationFormat.CurrentVersion.Should().Be(1);
        SecureSerializationFormat.VersionLength.Should().Be(1);
        SecureSerializationFormat.KeyIdLength.Should().Be(16);
        SecureSerializationFormat.NonceLength.Should().Be(12);
        SecureSerializationFormat.HmacLength.Should().Be(64);
    }
}
