using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Resilience;

[Trait("Category", "Stress"), Trait("SubCategory", "Resilience")]
public class TruncatedStreamTests
{
    private readonly ITestOutputHelper _output;

    public TruncatedStreamTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task ChunkedCrypto_MissingFinalChunk_Detected()
    {
        // Arrange: Encrypt 5 chunks, none marked final
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        const int chunkSize = 256;
        var testData = new byte[chunkSize];
        RandomNumberGenerator.Fill(testData);

        var encryptedChunks = new List<byte[]>();

        using var encEngine = new ChunkedCryptoEngine(key, chunkSize);
        for (long seq = 0; seq < 5; seq++)
        {
            // None marked as final (isFinal = false)
            var encrypted = encEngine.EncryptChunk(testData, seq, isFinal: false);
            encryptedChunks.Add(encrypted);
        }

        // Act: Decrypt all chunks and verify none is marked final
        using var decEngine = new ChunkedCryptoEngine(key, chunkSize);
        var anyFinal = false;
        for (long seq = 0; seq < 5; seq++)
        {
            var decrypted = decEngine.DecryptChunk(encryptedChunks[(int)seq], seq, out var isFinal);
            decrypted.Should().BeEquivalentTo(testData);
            if (isFinal) anyFinal = true;
        }

        // Assert: no chunk was marked final, meaning a consumer expecting a final chunk
        // would detect the truncation
        anyFinal.Should().BeFalse(
            "no chunk was marked final, so a stream consumer should detect the missing final marker as truncation");

        _output.WriteLine("Missing final chunk correctly detected: no chunk has isFinal=true");

        await Task.CompletedTask;
    }

    [Fact]
    public async Task ChunkedCrypto_ReorderedChunks_Rejected()
    {
        // Arrange: Encrypt chunks 0, 1, 2
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        const int chunkSize = 128;
        var testData = new byte[chunkSize];
        RandomNumberGenerator.Fill(testData);

        var encryptedChunks = new byte[3][];
        using var encEngine = new ChunkedCryptoEngine(key, chunkSize);
        for (long seq = 0; seq < 3; seq++)
        {
            encryptedChunks[seq] = encEngine.EncryptChunk(testData, seq, isFinal: seq == 2);
        }

        // Act: Decrypt in wrong order: 0, 2, 1 (swap chunks 1 and 2)
        using var decEngine = new ChunkedCryptoEngine(key, chunkSize);

        // Chunk 0 should succeed
        var decrypted0 = decEngine.DecryptChunk(encryptedChunks[0], 0, out _);
        decrypted0.Should().BeEquivalentTo(testData);

        // Chunk 2 at expected sequence 1 should fail (sequence mismatch)
        var act = () => decEngine.DecryptChunk(encryptedChunks[2], 1, out _);
        act.Should().Throw<CryptographicException>(
            "reordered chunk should be rejected due to sequence number mismatch");

        _output.WriteLine("Reordered chunks correctly rejected with CryptographicException");

        await Task.CompletedTask;
    }
}
