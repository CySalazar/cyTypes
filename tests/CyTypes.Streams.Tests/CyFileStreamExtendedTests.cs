using System.Security.Cryptography;
using CyTypes.Streams.File;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class CyFileStreamExtendedTests : IDisposable
{
    private readonly string _tempDir;

    public CyFileStreamExtendedTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "CyFileStreamExt_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void WriteRead_LargeFile_RoundTrips()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "large.cys");
        var data = new byte[32 * 1024]; // 32 KB
        RandomNumberGenerator.Fill(data);

        using (var fs = CyFileStream.CreateWrite(filePath, key))
        {
            fs.Write(data);
        }

        using var readFs = CyFileStream.OpenRead(filePath, key);
        var buffer = new byte[64 * 1024];
        var totalRead = 0;
        int read;
        while ((read = readFs.Read(buffer.AsSpan(totalRead))) > 0)
            totalRead += read;

        totalRead.Should().Be(data.Length);
        buffer.AsSpan(0, totalRead).ToArray().Should().Equal(data);
    }

    [Fact]
    public void WriteRead_CustomChunkSize_RoundTrips()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "custom_chunk.cys");
        var data = "Custom chunk size test data"u8.ToArray();

        using (var fs = CyFileStream.CreateWrite(filePath, key, new SecureFileOptions { ChunkSize = 16 }))
        {
            fs.Write(data);
        }

        using var readFs = CyFileStream.OpenRead(filePath, key);
        var buffer = new byte[256];
        var read = readFs.Read(buffer);

        buffer.AsSpan(0, read).ToArray().Should().Equal(data);
    }

    [Fact]
    public void WriteRead_NonAtomicMode_WritesDirectly()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "non_atomic.cys");

        using (var fs = CyFileStream.CreateWrite(filePath, key, new SecureFileOptions { AtomicWrite = false }))
        {
            // File should exist at the target path during write
            System.IO.File.Exists(filePath).Should().BeTrue();
            fs.Write("data"u8.ToArray());
        }

        System.IO.File.Exists(filePath).Should().BeTrue();
    }

    [Fact]
    public void OpenRead_NonExistentFile_Throws()
    {
        var key = GenerateKey();
        var act = () => CyFileStream.OpenRead(Path.Combine(_tempDir, "nope.cys"), key);
        act.Should().Throw<FileNotFoundException>();
    }

    [Fact]
    public void Read_WrongKey_ThrowsCryptographicException()
    {
        var key1 = GenerateKey();
        var key2 = GenerateKey();
        var filePath = Path.Combine(_tempDir, "wrong_key.cys");

        using (var fs = CyFileStream.CreateWrite(filePath, key1))
        {
            fs.Write("secret"u8.ToArray());
        }

        using var readFs = CyFileStream.OpenRead(filePath, key2);
        var buffer = new byte[256];
        var act = () => readFs.Read(buffer);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Stream_Property_ReturnsCyStream()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "stream_prop.cys");

        using var fs = CyFileStream.CreateWrite(filePath, key);
        fs.Stream.Should().NotBeNull();
        fs.Stream.CanWrite.Should().BeTrue();
    }

    [Fact]
    public async Task DisposeAsync_ClosesFile()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "async_dispose.cys");

        var fs = CyFileStream.CreateWrite(filePath, key);
        fs.Write("test"u8.ToArray());
        await fs.DisposeAsync();

        System.IO.File.Exists(filePath).Should().BeTrue();

        // Should be able to open the file now (no lingering handles)
        using var readFs = CyFileStream.OpenRead(filePath, key);
        var buffer = new byte[256];
        var read = readFs.Read(buffer);
        read.Should().BeGreaterThan(0);
    }

    [Fact]
    public void WriteRead_EmptyFile_RoundTrips()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "empty.cys");

        using (var fs = CyFileStream.CreateWrite(filePath, key))
        {
            // Write nothing
        }

        System.IO.File.Exists(filePath).Should().BeTrue();
        new FileInfo(filePath).Length.Should().BeGreaterThan(0); // Header still written
    }
}
