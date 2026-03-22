using System.Diagnostics;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Streams.File;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Integration;

[Trait("Category", "Stress"), Trait("SubCategory", "Integration")]
public class StreamPipelineStressTests
{
    private readonly ITestOutputHelper _output;

    public StreamPipelineStressTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task ChunkedEngine_WriterReader_Pipeline()
    {
        // Arrange: Write 1000 chunks through ChunkedCryptoEngine, decrypt all
        const int chunkCount = 1000;
        const int chunkSize = 512;
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var rng = new Random(42);
        var originalChunks = new byte[chunkCount][];
        for (var i = 0; i < chunkCount; i++)
        {
            originalChunks[i] = new byte[chunkSize];
            rng.NextBytes(originalChunks[i]);
        }

        var encryptedChunks = new byte[chunkCount][];
        var counter = new ThroughputCounter();

        // Act: Encrypt all chunks
        var swEncrypt = Stopwatch.StartNew();
        using (var encEngine = new ChunkedCryptoEngine(key, chunkSize))
        {
            for (var i = 0; i < chunkCount; i++)
            {
                var isFinal = i == chunkCount - 1;
                encryptedChunks[i] = encEngine.EncryptChunk(originalChunks[i], i, isFinal);
                counter.Increment();
            }
        }
        swEncrypt.Stop();

        // Act: Decrypt all chunks
        var swDecrypt = Stopwatch.StartNew();
        using (var decEngine = new ChunkedCryptoEngine(key, chunkSize))
        {
            for (var i = 0; i < chunkCount; i++)
            {
                var decrypted = decEngine.DecryptChunk(encryptedChunks[i], i, out var isFinal);

                // Assert: each chunk matches
                decrypted.Should().BeEquivalentTo(originalChunks[i],
                    $"chunk {i} must decrypt to original data");

                if (i == chunkCount - 1)
                    isFinal.Should().BeTrue("last chunk should be marked as final");
            }
        }
        swDecrypt.Stop();

        var totalBytes = chunkCount * chunkSize;
        var encMBps = (totalBytes / 1024.0 / 1024.0) / swEncrypt.Elapsed.TotalSeconds;
        var decMBps = (totalBytes / 1024.0 / 1024.0) / swDecrypt.Elapsed.TotalSeconds;

        _output.WriteLine($"Pipeline: {chunkCount} chunks x {chunkSize} bytes = {totalBytes / 1024.0:F0} KB");
        _output.WriteLine($"Encrypt: {swEncrypt.Elapsed.TotalMilliseconds:F2}ms ({encMBps:F2} MB/s)");
        _output.WriteLine($"Decrypt: {swDecrypt.Elapsed.TotalMilliseconds:F2}ms ({decMBps:F2} MB/s)");
        _output.WriteLine(counter.Summary);

        await Task.CompletedTask;
    }

    [Fact]
    public async Task CyFileStream_WriterReader_Pipeline()
    {
        // Arrange: Write multiple byte arrays to CyFileStream, read back all, verify
        var tempPath = Path.GetTempFileName();
        var passphrase = "pipeline-test-" + Guid.NewGuid();
        var rng = new Random(42);

        const int blockCount = 50;
        const int blockSize = 4096;
        var originalBlocks = new byte[blockCount][];
        for (var i = 0; i < blockCount; i++)
        {
            originalBlocks[i] = new byte[blockSize];
            rng.NextBytes(originalBlocks[i]);
        }

        try
        {
            // Act: Write all blocks
            using (var writer = CyFileStream.CreateWrite(tempPath, passphrase))
            {
                foreach (var block in originalBlocks)
                {
                    writer.Write(block);
                }
            }

            // Act: Read back all data
            var totalSize = blockCount * blockSize;
            var readData = new byte[totalSize];
            int totalRead;
            using (var reader = CyFileStream.OpenRead(tempPath, passphrase))
            {
                totalRead = 0;
                while (totalRead < totalSize)
                {
                    var bytesRead = reader.Read(readData.AsSpan(totalRead));
                    if (bytesRead == 0) break;
                    totalRead += bytesRead;
                }
            }

            // Assert: concatenated blocks should match
            var expectedData = new byte[totalSize];
            for (var i = 0; i < blockCount; i++)
            {
                originalBlocks[i].CopyTo(expectedData.AsSpan(i * blockSize));
            }

            totalRead.Should().Be(totalSize, "all bytes should be read back");
            readData.Should().BeEquivalentTo(expectedData, "file pipeline round-trip must preserve data integrity");

            _output.WriteLine($"CyFileStream pipeline: {blockCount} blocks x {blockSize} bytes = {totalSize / 1024.0:F0} KB");
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }

        await Task.CompletedTask;
    }
}
