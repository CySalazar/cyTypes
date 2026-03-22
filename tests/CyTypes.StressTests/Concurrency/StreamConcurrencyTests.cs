using System.Collections.Concurrent;
using CyTypes.Streams.File;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class StreamConcurrencyTests : IDisposable
{
    private readonly string _tempDir;

    public StreamConcurrencyTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "CyTypes_StreamStress_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public async Task CyFileStream_ConcurrentReaders_SamePath()
    {
        // Arrange: write an encrypted file, then have N readers open and read it concurrently
        var threadCount = StressTestConfig.ConcurrentThreads;
        var filePath = Path.Combine(_tempDir, "concurrent_read_test.cyf");
        const string passphrase = "stress-test-passphrase";
        var testData = new byte[4096];
        Random.Shared.NextBytes(testData);

        // Write the file
        using (var writer = CyFileStream.CreateWrite(filePath, passphrase))
        {
            writer.Write(testData);
        }

        // Act: N readers concurrently open and read
        var barrier = new Barrier(threadCount);
        var results = new ConcurrentBag<(int ThreadId, bool Success, int BytesRead)>();
        var exceptions = new ConcurrentBag<Exception>();

        var tasks = Enumerable.Range(0, threadCount).Select(threadId => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                using var reader = CyFileStream.OpenRead(filePath, passphrase);
                var buffer = new byte[testData.Length + 1024]; // Extra room
                var totalRead = 0;
                int bytesRead;
                do
                {
                    bytesRead = reader.Read(buffer.AsSpan(totalRead));
                    totalRead += bytesRead;
                } while (bytesRead > 0);

                var readData = buffer[..totalRead];
                var matches = readData.SequenceEqual(testData);
                results.Add((threadId, matches, totalRead));
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("concurrent readers on the same encrypted file must not fail");
        results.Should().HaveCount(threadCount);
        results.Should().AllSatisfy(r =>
        {
            r.Success.Should().BeTrue($"thread {r.ThreadId} must read correct data");
            r.BytesRead.Should().Be(testData.Length,
                $"thread {r.ThreadId} must read exactly {testData.Length} bytes");
        });
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup
        }
    }
}
