using System.Security;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Resilience;

[Trait("Category", "Stress"), Trait("SubCategory", "Resilience")]
public class TamperedEnvelopeTests
{
    private readonly ITestOutputHelper _output;

    public TamperedEnvelopeTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task SecureSerializationFormat_TamperedHmac_Rejected()
    {
        // Arrange
        var ciphertext = new byte[64];
        RandomNumberGenerator.Fill(ciphertext);
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);

        var envelope = SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);

        // Flip bits in the HMAC region (last 64 bytes)
        var tampered = (byte[])envelope.Clone();
        tampered[^1] ^= 0x01;
        tampered[^32] ^= 0xFF;

        // Act & Assert
        var act = () => SecureSerializationFormat.Deserialize(tampered, hmacKey);
        act.Should().Throw<SecurityException>("tampered HMAC should be rejected");

        _output.WriteLine("Tampered HMAC correctly rejected");

        await Task.CompletedTask;
    }

    [Fact]
    public async Task SecureSerializationFormat_WrongVersion_Rejected()
    {
        // Arrange
        var ciphertext = new byte[64];
        RandomNumberGenerator.Fill(ciphertext);
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);

        var envelope = SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);

        // Change the version byte (byte 0)
        var tampered = (byte[])envelope.Clone();
        tampered[0] = 0xFF; // Invalid version

        // Act & Assert
        var act = () => SecureSerializationFormat.Deserialize(tampered, hmacKey);
        act.Should().Throw<ArgumentException>("unsupported version should be rejected");

        _output.WriteLine("Wrong version correctly rejected");

        await Task.CompletedTask;
    }

    [Fact]
    public async Task SecureSerializationFormat_TruncatedEnvelope_Rejected()
    {
        // Arrange: create an envelope and truncate it below minimum length
        var ciphertext = new byte[64];
        RandomNumberGenerator.Fill(ciphertext);
        var keyId = Guid.NewGuid();
        var hmacKey = new byte[32];
        RandomNumberGenerator.Fill(hmacKey);

        var envelope = SecureSerializationFormat.Serialize(ciphertext, keyId, hmacKey);

        // Minimum envelope: version(1) + keyId(16) + nonce(12) + hmac(64) = 93 bytes
        // Truncate to less than minimum
        var truncated = new byte[50];
        Array.Copy(envelope, truncated, truncated.Length);

        // Act & Assert
        var act = () => SecureSerializationFormat.Deserialize(truncated, hmacKey);
        act.Should().Throw<ArgumentException>("truncated envelope below minimum size should be rejected");

        _output.WriteLine("Truncated envelope correctly rejected");

        await Task.CompletedTask;
    }
}
