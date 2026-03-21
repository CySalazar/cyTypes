using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class StreamSecurityTests
{
    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void TamperedChunk_DetectedOnDecrypt()
    {
        var key = GenerateKey();
        using var engine = new ChunkedCryptoEngine(key, 256);

        var encrypted = engine.EncryptChunk("sensitive data"u8.ToArray(), 0, true);

        // Tamper with a byte in the ciphertext area
        encrypted[25] ^= 0xFF;

        var act = () => engine.DecryptChunk(encrypted, 0, out _);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void TruncatedStream_DetectedByMissingFinalChunk()
    {
        var key = GenerateKey();
        using var encEngine = new ChunkedCryptoEngine(key, 256);
        using var decEngine = new ChunkedCryptoEngine(key, 256);

        // Encrypt two chunks, first non-final
        var chunk0 = encEngine.EncryptChunk("part 1"u8.ToArray(), 0, false);
        // Don't encrypt the final chunk — simulates truncation

        var decrypted = decEngine.DecryptChunk(chunk0, 0, out var isFinal);
        decrypted.Should().NotBeEmpty();
        isFinal.Should().BeFalse(); // Stream truncated — final never received
    }

    [Fact]
    public void ReplayChunk_DetectedBySequenceNumber()
    {
        var key = GenerateKey();
        using var encEngine = new ChunkedCryptoEngine(key, 256);
        using var decEngine = new ChunkedCryptoEngine(key, 256);

        var chunk0 = encEngine.EncryptChunk("first"u8.ToArray(), 0, false);
        var chunk1 = encEngine.EncryptChunk("second"u8.ToArray(), 1, true);

        // Decrypt chunk 0 normally
        decEngine.DecryptChunk(chunk0, 0, out _);

        // Try to replay chunk 0 at position 1 — should fail
        var act = () => decEngine.DecryptChunk(chunk0, 1, out _);
        act.Should().Throw<CryptographicException>()
            .WithMessage("*sequence number mismatch*");
    }

    [Fact]
    public void ReorderedChunks_Detected()
    {
        var key = GenerateKey();
        using var encEngine = new ChunkedCryptoEngine(key, 256);
        using var decEngine = new ChunkedCryptoEngine(key, 256);

        var chunk0 = encEngine.EncryptChunk("A"u8.ToArray(), 0, false);
        var chunk1 = encEngine.EncryptChunk("B"u8.ToArray(), 1, true);

        // Try to decrypt chunk1 first (at position 0)
        var act = () => decEngine.DecryptChunk(chunk1, 0, out _);
        act.Should().Throw<CryptographicException>()
            .WithMessage("*sequence number mismatch*");
    }

    [Fact]
    public void StreamHeader_TamperedMagic_Detected()
    {
        var header = new byte[StreamSerializationFormat.HeaderSize];
        StreamSerializationFormat.WriteHeader(header, Guid.NewGuid(), 65536);

        // Tamper magic bytes
        header[0] = (byte)'X';

        var act = () => StreamSerializationFormat.ReadHeader(header);
        act.Should().Throw<System.Security.SecurityException>()
            .WithMessage("*magic*");
    }

    [Fact]
    public void StreamFooter_TamperedHmac_Detected()
    {
        var key = GenerateKey();
        var hmacKey = StreamSerializationFormat.DeriveHmacKey(key);
        var authData = "authenticated content"u8.ToArray();

        var footer = new byte[StreamSerializationFormat.FooterSize];
        StreamSerializationFormat.WriteFooter(footer, 5, hmacKey, authData);

        // Tamper HMAC
        footer[10] ^= 0xFF;

        var act = () => StreamSerializationFormat.ReadFooter(footer, hmacKey, authData);
        act.Should().Throw<System.Security.SecurityException>()
            .WithMessage("*HMAC*");

        CryptographicOperations.ZeroMemory(hmacKey);
    }
}
