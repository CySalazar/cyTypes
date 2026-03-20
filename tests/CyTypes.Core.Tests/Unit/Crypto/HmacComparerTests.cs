using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class HmacComparerTests
{
    private static byte[] GenerateKey(int length = 64)
    {
        var key = new byte[length];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void Compute_returns_64_bytes()
    {
        var key = GenerateKey();
        var data = "test data"u8.ToArray();

        var mac = HmacComparer.Compute(key, data);

        mac.Should().HaveCount(64, "HMAC-SHA512 produces a 64-byte digest");
    }

    [Fact]
    public void Verify_returns_true_for_correct_HMAC()
    {
        var key = GenerateKey();
        var data = "verify me"u8.ToArray();

        var mac = HmacComparer.Compute(key, data);
        var result = HmacComparer.Verify(key, data, mac);

        result.Should().BeTrue();
    }

    [Fact]
    public void Verify_returns_false_for_tampered_HMAC()
    {
        var key = GenerateKey();
        var data = "tamper test"u8.ToArray();

        var mac = HmacComparer.Compute(key, data);
        mac[mac.Length / 2] ^= 0xFF;

        var result = HmacComparer.Verify(key, data, mac);

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_returns_false_for_wrong_key()
    {
        var key = GenerateKey();
        var wrongKey = GenerateKey();
        var data = "wrong key test"u8.ToArray();

        var mac = HmacComparer.Compute(key, data);
        var result = HmacComparer.Verify(wrongKey, data, mac);

        result.Should().BeFalse();
    }

    [Fact]
    public void Same_key_and_data_always_produces_same_HMAC()
    {
        var key = GenerateKey();
        var data = "determinism"u8.ToArray();

        var mac1 = HmacComparer.Compute(key, data);
        var mac2 = HmacComparer.Compute(key, data);

        mac1.Should().Equal(mac2);
    }

    [Fact]
    public void Different_data_produces_different_HMAC()
    {
        var key = GenerateKey();
        var data1 = "message one"u8.ToArray();
        var data2 = "message two"u8.ToArray();

        var mac1 = HmacComparer.Compute(key, data1);
        var mac2 = HmacComparer.Compute(key, data2);

        mac1.Should().NotEqual(mac2);
    }
}
