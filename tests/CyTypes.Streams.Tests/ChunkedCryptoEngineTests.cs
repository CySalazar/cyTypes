using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class ChunkedCryptoEngineTests
{
    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_ReturnsOriginalData()
    {
        var key = GenerateKey();
        using var engine = new ChunkedCryptoEngine(key, 1024);
        var plaintext = "Hello, CyStream!"u8.ToArray();

        var encrypted = engine.EncryptChunk(plaintext, 0, true);
        var decrypted = engine.DecryptChunk(encrypted, 0, out var isFinal);

        decrypted.Should().Equal(plaintext);
        isFinal.Should().BeTrue();
    }

    [Fact]
    public void EncryptDecrypt_MultipleChunks_PreservesOrder()
    {
        var key = GenerateKey();
        using var encEngine = new ChunkedCryptoEngine(key, 1024);
        using var decEngine = new ChunkedCryptoEngine(key, 1024);

        var chunks = new[]
        {
            "Chunk 0"u8.ToArray(),
            "Chunk 1"u8.ToArray(),
            "Chunk 2"u8.ToArray()
        };

        for (int i = 0; i < chunks.Length; i++)
        {
            var isFinalChunk = i == chunks.Length - 1;
            var encrypted = encEngine.EncryptChunk(chunks[i], i, isFinalChunk);
            var decrypted = decEngine.DecryptChunk(encrypted, i, out var isFinal);

            decrypted.Should().Equal(chunks[i]);
            isFinal.Should().Be(isFinalChunk);
        }
    }

    [Fact]
    public void DecryptChunk_WrongSequenceNumber_Throws()
    {
        var key = GenerateKey();
        using var engine = new ChunkedCryptoEngine(key, 1024);
        var plaintext = "test"u8.ToArray();

        var encrypted = engine.EncryptChunk(plaintext, 0, false);

        var act = () => engine.DecryptChunk(encrypted, 1, out _);
        act.Should().Throw<CryptographicException>()
            .WithMessage("*sequence number mismatch*");
    }

    [Fact]
    public void DecryptChunk_TamperedData_Throws()
    {
        var key = GenerateKey();
        using var engine = new ChunkedCryptoEngine(key, 1024);
        var plaintext = "test data"u8.ToArray();

        var encrypted = engine.EncryptChunk(plaintext, 0, false);

        // Tamper with ciphertext byte
        encrypted[20] ^= 0xFF;

        var act = () => engine.DecryptChunk(encrypted, 0, out _);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void DecryptChunk_TruncatedChunk_Throws()
    {
        var key = GenerateKey();
        using var engine = new ChunkedCryptoEngine(key, 1024);

        var tooShort = new byte[10]; // Less than overhead

        var act = () => engine.DecryptChunk(tooShort, 0, out _);
        act.Should().Throw<CryptographicException>()
            .WithMessage("*too short*");
    }

    [Fact]
    public void FinalChunkMarker_DetectedCorrectly()
    {
        var key = GenerateKey();
        using var encEngine = new ChunkedCryptoEngine(key, 1024);
        using var decEngine = new ChunkedCryptoEngine(key, 1024);
        var plaintext = "data"u8.ToArray();

        var nonFinal = encEngine.EncryptChunk(plaintext, 0, false);
        var final = encEngine.EncryptChunk(plaintext, 1, true);

        decEngine.DecryptChunk(nonFinal, 0, out var isFinal1);
        isFinal1.Should().BeFalse();

        decEngine.DecryptChunk(final, 1, out var isFinal2);
        isFinal2.Should().BeTrue();
    }

    [Fact]
    public void EmptyPlaintext_RoundTrips()
    {
        var key = GenerateKey();
        using var engine = new ChunkedCryptoEngine(key, 1024);

        var encrypted = engine.EncryptChunk([], 0, true);
        var decrypted = engine.DecryptChunk(encrypted, 0, out var isFinal);

        decrypted.Should().BeEmpty();
        isFinal.Should().BeTrue();
    }

    [Fact]
    public void Constructor_InvalidKeyLength_Throws()
    {
        var act = () => new ChunkedCryptoEngine(new byte[16], 1024);
        act.Should().Throw<ArgumentException>().WithMessage("*256 bits*");
    }

    [Fact]
    public void GetEncryptedChunkSize_ReturnsCorrectValue()
    {
        // Overhead = 8 (seq) + 12 (nonce) + 16 (tag) = 36
        ChunkedCryptoEngine.GetEncryptedChunkSize(100).Should().Be(136);
        ChunkedCryptoEngine.GetEncryptedChunkSize(0).Should().Be(36);
    }
}
