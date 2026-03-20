using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class HkdfKeyDerivationTests
{
    private static byte[] GenerateIkm(int length = 32)
    {
        var ikm = new byte[length];
        RandomNumberGenerator.Fill(ikm);
        return ikm;
    }

    [Fact]
    public void DeriveKey_produces_consistent_output_for_same_inputs()
    {
        var ikm = GenerateIkm();
        var salt = "test-salt"u8.ToArray();
        var info = "test-info"u8.ToArray();

        var result1 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, info);
        var result2 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, info);

        result1.Should().Equal(result2);
    }

    [Fact]
    public void DeriveKey_with_different_salt_produces_different_output()
    {
        var ikm = GenerateIkm();
        var salt1 = "salt-one"u8.ToArray();
        var salt2 = "salt-two"u8.ToArray();
        var info = "shared-info"u8.ToArray();

        var result1 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt1, info);
        var result2 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt2, info);

        result1.Should().NotEqual(result2);
    }

    [Fact]
    public void DeriveKey_with_different_info_produces_different_output()
    {
        var ikm = GenerateIkm();
        var salt = "shared-salt"u8.ToArray();
        var info1 = "info-one"u8.ToArray();
        var info2 = "info-two"u8.ToArray();

        var result1 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, info1);
        var result2 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, info2);

        result1.Should().NotEqual(result2);
    }

    [Fact]
    public void Output_length_matches_requested_length()
    {
        var ikm = GenerateIkm();

        var result16 = HkdfKeyDerivation.DeriveKey(ikm, 16);
        var result64 = HkdfKeyDerivation.DeriveKey(ikm, 64);

        result16.Should().HaveCount(16);
        result64.Should().HaveCount(64);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Throws_for_outputLength_less_than_or_equal_to_zero(int outputLength)
    {
        var ikm = GenerateIkm();

        var act = () => HkdfKeyDerivation.DeriveKey(ikm, outputLength);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void RFC5869_style_derivation_is_deterministic_and_correct_length()
    {
        // RFC 5869 Test Vector 1 IKM (adapted — exact output differs since we use SHA-512)
        var ikm = new byte[22];
        Array.Fill(ikm, (byte)0x0b);

        var salt = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
        var info = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
        const int outputLength = 42;

        var result1 = HkdfKeyDerivation.DeriveKey(ikm, outputLength, salt, info);
        var result2 = HkdfKeyDerivation.DeriveKey(ikm, outputLength, salt, info);

        result1.Should().HaveCount(outputLength);
        result1.Should().Equal(result2, "HKDF-SHA512 must be deterministic for the same inputs");
    }
}
