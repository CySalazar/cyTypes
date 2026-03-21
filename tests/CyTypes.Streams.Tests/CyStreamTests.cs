using System.Security.Cryptography;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class CyStreamTests
{
    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void WriteRead_RoundTrip_ReturnsOriginalData()
    {
        var key = GenerateKey();
        var data = "Hello, encrypted stream world!"u8.ToArray();
        var memoryStream = new MemoryStream();

        // Write
        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 64, leaveOpen: true))
        {
            writer.Write(data, 0, data.Length);
        }

        // Read
        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[1024];
        var totalRead = 0;
        int read;
        while ((read = reader.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
        {
            totalRead += read;
        }

        buffer.AsSpan(0, totalRead).ToArray().Should().Equal(data);
    }

    [Fact]
    public void WriteRead_MultipleWrites_ReturnsAllData()
    {
        var key = GenerateKey();
        var memoryStream = new MemoryStream();

        // Write multiple small pieces
        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 32, leaveOpen: true))
        {
            writer.Write("Hello, "u8.ToArray(), 0, 7);
            writer.Write("World!"u8.ToArray(), 0, 6);
        }

        // Read back
        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[256];
        var totalRead = 0;
        int read;
        while ((read = reader.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
        {
            totalRead += read;
        }

        System.Text.Encoding.UTF8.GetString(buffer, 0, totalRead).Should().Be("Hello, World!");
    }

    [Fact]
    public void WriteRead_LargeData_SpansMultipleChunks()
    {
        var key = GenerateKey();
        var data = new byte[1024];
        RandomNumberGenerator.Fill(data);
        var memoryStream = new MemoryStream();

        // Write with small chunk size to force multiple chunks
        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 128, leaveOpen: true))
        {
            writer.Write(data, 0, data.Length);
        }

        // Read
        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[2048];
        var totalRead = 0;
        int read;
        while ((read = reader.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
        {
            totalRead += read;
        }

        totalRead.Should().Be(1024);
        buffer.AsSpan(0, totalRead).ToArray().Should().Equal(data);
    }

    [Fact]
    public void Read_WrongKey_Throws()
    {
        var key1 = GenerateKey();
        var key2 = GenerateKey();
        var data = "secret"u8.ToArray();
        var memoryStream = new MemoryStream();

        using (var writer = CyStream.CreateWriter(memoryStream, key1, Guid.NewGuid(), 64, leaveOpen: true))
        {
            writer.Write(data, 0, data.Length);
        }

        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key2);
        var buffer = new byte[256];

        var act = () => reader.Read(buffer, 0, buffer.Length);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void CanSeek_ReturnsFalse()
    {
        var key = GenerateKey();
        var memoryStream = new MemoryStream();
        using var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), leaveOpen: true);

        writer.CanSeek.Should().BeFalse();
    }

    [Fact]
    public void Seek_ThrowsNotSupported()
    {
        var key = GenerateKey();
        var memoryStream = new MemoryStream();
        using var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), leaveOpen: true);

        var act = () => writer.Seek(0, SeekOrigin.Begin);
        act.Should().Throw<NotSupportedException>();
    }
}
