using System.Diagnostics;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Streams.File;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Throughput;

[Trait("Category", "Stress"), Trait("SubCategory", "Throughput")]
public class StreamThroughputTests
{
    private readonly ITestOutputHelper _output;

    public StreamThroughputTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task CyStream_WriteRead_LargeVolume()
    {
        // Arrange: 10 MB of data, chunked through ChunkedCryptoEngine
        const int totalBytes = 10 * 1024 * 1024;
        const int chunkSize = 65536;
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var plainData = new byte[totalBytes];
        RandomNumberGenerator.Fill(plainData);

        var encryptedChunks = new List<byte[]>();
        var counter = new ThroughputCounter();

        // Act: Encrypt
        var swEncrypt = Stopwatch.StartNew();
        using (var encEngine = new ChunkedCryptoEngine(key, chunkSize))
        {
            var offset = 0;
            long seq = 0;
            while (offset < totalBytes)
            {
                var remaining = totalBytes - offset;
                var currentChunkSize = Math.Min(chunkSize, remaining);
                var isFinal = offset + currentChunkSize >= totalBytes;
                var chunk = new byte[currentChunkSize];
                Array.Copy(plainData, offset, chunk, 0, currentChunkSize);
                var encrypted = encEngine.EncryptChunk(chunk, seq, isFinal);
                encryptedChunks.Add(encrypted);
                offset += currentChunkSize;
                seq++;
                counter.Increment();
            }
        }
        swEncrypt.Stop();

        // Act: Decrypt
        var decryptedData = new byte[totalBytes];
        var swDecrypt = Stopwatch.StartNew();
        using (var decEngine = new ChunkedCryptoEngine(key, chunkSize))
        {
            var offset = 0;
            long seq = 0;
            foreach (var encChunk in encryptedChunks)
            {
                var decrypted = decEngine.DecryptChunk(encChunk, seq, out var isFinal);
                Array.Copy(decrypted, 0, decryptedData, offset, decrypted.Length);
                offset += decrypted.Length;
                seq++;

                if (isFinal)
                    break;
            }
        }
        swDecrypt.Stop();

        // Assert
        decryptedData.Should().BeEquivalentTo(plainData, "round-trip must preserve data integrity");

        var encryptMBps = (totalBytes / 1024.0 / 1024.0) / swEncrypt.Elapsed.TotalSeconds;
        var decryptMBps = (totalBytes / 1024.0 / 1024.0) / swDecrypt.Elapsed.TotalSeconds;

        _output.WriteLine($"Data size: {totalBytes / 1024.0 / 1024.0:F2} MB");
        _output.WriteLine($"Encrypt: {swEncrypt.Elapsed.TotalMilliseconds:F2}ms ({encryptMBps:F2} MB/s)");
        _output.WriteLine($"Decrypt: {swDecrypt.Elapsed.TotalMilliseconds:F2}ms ({decryptMBps:F2} MB/s)");
        _output.WriteLine($"Chunks processed: {counter.Summary}");

        await Task.CompletedTask;
    }

    [Fact]
    public async Task CyFileStream_LargeFile_Throughput()
    {
        // Arrange
        const int totalBytes = 10 * 1024 * 1024;
        var tempPath = Path.GetTempFileName();
        var passphrase = "stress-test-passphrase-" + Guid.NewGuid();
        var plainData = new byte[totalBytes];
        RandomNumberGenerator.Fill(plainData);

        try
        {
            // Act: Write
            var swWrite = Stopwatch.StartNew();
            using (var writer = CyFileStream.CreateWrite(tempPath, passphrase))
            {
                var offset = 0;
                const int writeChunkSize = 65536;
                while (offset < totalBytes)
                {
                    var size = Math.Min(writeChunkSize, totalBytes - offset);
                    writer.Write(plainData.AsSpan(offset, size));
                    offset += size;
                }
            }
            swWrite.Stop();

            // Act: Read
            var readData = new byte[totalBytes];
            var swRead = Stopwatch.StartNew();
            using (var reader = CyFileStream.OpenRead(tempPath, passphrase))
            {
                var totalRead = 0;
                while (totalRead < totalBytes)
                {
                    var bytesRead = reader.Read(readData.AsSpan(totalRead));
                    if (bytesRead == 0) break;
                    totalRead += bytesRead;
                }
            }
            swRead.Stop();

            // Assert
            readData.Should().BeEquivalentTo(plainData, "file round-trip must preserve data integrity");

            var writeMBps = (totalBytes / 1024.0 / 1024.0) / swWrite.Elapsed.TotalSeconds;
            var readMBps = (totalBytes / 1024.0 / 1024.0) / swRead.Elapsed.TotalSeconds;

            _output.WriteLine($"File size: {totalBytes / 1024.0 / 1024.0:F2} MB");
            _output.WriteLine($"Write: {swWrite.Elapsed.TotalMilliseconds:F2}ms ({writeMBps:F2} MB/s)");
            _output.WriteLine($"Read: {swRead.Elapsed.TotalMilliseconds:F2}ms ({readMBps:F2} MB/s)");
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }

        await Task.CompletedTask;
    }

    [Fact]
    public async Task ChunkedCryptoEngine_KeyRatchet_Boundary()
    {
        // Arrange: Use small chunk size (64 bytes) and encrypt around the 2^20 boundary
        // to trigger key ratchet. ChunkedCryptoEngine ratchets every 2^20 chunks.
        const int chunkSize = 64;
        const long ratchetInterval = 1L << 20; // 1,048,576
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var testData = new byte[chunkSize];
        RandomNumberGenerator.Fill(testData);

        // Encrypt chunks near the ratchet boundary
        var boundaryStart = ratchetInterval - 5;
        var boundaryEnd = ratchetInterval + 5;
        var encryptedChunks = new Dictionary<long, byte[]>();

        using var encEngine = new ChunkedCryptoEngine(key, chunkSize);

        // We must encrypt sequentially from 0, but we can skip ahead by encrypting
        // small chunks up to the boundary. For performance, encrypt from boundaryStart-5.
        // However, the engine tracks ratchet generation based on seq/interval, so we can
        // start from the boundary region by creating a new engine and manually encrypting.
        // Actually, we need sequential encryption. Let's encrypt the boundary range.
        // The engine ratchets based on sequence number, not actual count.
        for (var seq = boundaryStart; seq <= boundaryEnd; seq++)
        {
            var isFinal = seq == boundaryEnd;
            var encrypted = encEngine.EncryptChunk(testData, seq, isFinal);
            encryptedChunks[seq] = encrypted;
        }

        // Act: Decrypt all chunks around the boundary
        using var decEngine = new ChunkedCryptoEngine(key, chunkSize);
        for (var seq = boundaryStart; seq <= boundaryEnd; seq++)
        {
            var decrypted = decEngine.DecryptChunk(encryptedChunks[seq], seq, out var isFinal);

            // Assert
            decrypted.Should().BeEquivalentTo(testData,
                $"decryption at sequence {seq} (ratchet boundary) must produce original data");

            if (seq == boundaryEnd)
                isFinal.Should().BeTrue();
        }

        _output.WriteLine($"Successfully encrypted/decrypted chunks at ratchet boundary ({boundaryStart} to {boundaryEnd})");
        _output.WriteLine($"Ratchet interval: {ratchetInterval}");

        await Task.CompletedTask;
    }
}
