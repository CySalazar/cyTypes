using System.Security.Cryptography;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class CyStreamExtendedTests
{
    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void WriteRead_EmptyData_ReturnsEmpty()
    {
        var key = GenerateKey();
        var memoryStream = new MemoryStream();

        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 64, leaveOpen: true))
        {
            // Write nothing, just close
        }

        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[256];
        var read = reader.Read(buffer, 0, buffer.Length);

        read.Should().Be(0);
    }

    [Fact]
    public void WriteRead_SingleByte_RoundTrips()
    {
        var key = GenerateKey();
        var data = new byte[] { 0x42 };
        var memoryStream = new MemoryStream();

        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 64, leaveOpen: true))
        {
            writer.Write(data, 0, 1);
        }

        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[256];
        var read = reader.Read(buffer, 0, buffer.Length);

        read.Should().Be(1);
        buffer[0].Should().Be(0x42);
    }

    [Fact]
    public void WriteRead_ExactlyOneChunk_RoundTrips()
    {
        var key = GenerateKey();
        var chunkSize = 128;
        var data = new byte[chunkSize];
        RandomNumberGenerator.Fill(data);
        var memoryStream = new MemoryStream();

        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), chunkSize, leaveOpen: true))
        {
            writer.Write(data, 0, data.Length);
        }

        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[1024];
        var totalRead = 0;
        int read;
        while ((read = reader.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
            totalRead += read;

        totalRead.Should().Be(chunkSize);
        buffer.AsSpan(0, totalRead).ToArray().Should().Equal(data);
    }

    [Fact]
    public void Writer_CanRead_ReturnsFalse()
    {
        var key = GenerateKey();
        using var writer = CyStream.CreateWriter(new MemoryStream(), key, Guid.NewGuid());
        writer.CanRead.Should().BeFalse();
        writer.CanWrite.Should().BeTrue();
    }

    [Fact]
    public void Reader_CanWrite_ReturnsFalse()
    {
        var key = GenerateKey();
        var ms = new MemoryStream();
        using (var writer = CyStream.CreateWriter(ms, key, Guid.NewGuid(), leaveOpen: true))
        {
            writer.Write("data"u8.ToArray(), 0, 4);
        }

        ms.Position = 0;
        using var reader = CyStream.CreateReader(ms, key);
        reader.CanRead.Should().BeTrue();
        reader.CanWrite.Should().BeFalse();
    }

    [Fact]
    public void SetLength_ThrowsNotSupported()
    {
        var key = GenerateKey();
        using var writer = CyStream.CreateWriter(new MemoryStream(), key, Guid.NewGuid());

        var act = () => writer.SetLength(100);
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Position_Get_ThrowsNotSupported()
    {
        var key = GenerateKey();
        using var writer = CyStream.CreateWriter(new MemoryStream(), key, Guid.NewGuid());

        var act = () => _ = writer.Position;
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Length_ThrowsNotSupported()
    {
        var key = GenerateKey();
        using var writer = CyStream.CreateWriter(new MemoryStream(), key, Guid.NewGuid());

        var act = () => _ = writer.Length;
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var key = GenerateKey();
        var writer = CyStream.CreateWriter(new MemoryStream(), key, Guid.NewGuid());
        writer.Dispose();
        // Second dispose should not throw
        writer.Dispose();
    }

    [Fact]
    public async Task DisposeAsync_IsIdempotent()
    {
        var key = GenerateKey();
        var writer = CyStream.CreateWriter(new MemoryStream(), key, Guid.NewGuid());
        await writer.DisposeAsync();
        await writer.DisposeAsync();
    }

    [Fact]
    public void WriteRead_VeryLargeData_SpansManyChunks()
    {
        var key = GenerateKey();
        var data = new byte[64 * 1024]; // 64 KB
        RandomNumberGenerator.Fill(data);
        var memoryStream = new MemoryStream();

        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 4096, leaveOpen: true))
        {
            writer.Write(data, 0, data.Length);
        }

        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[128 * 1024];
        var totalRead = 0;
        int read;
        while ((read = reader.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
            totalRead += read;

        totalRead.Should().Be(64 * 1024);
        buffer.AsSpan(0, totalRead).ToArray().Should().Equal(data);
    }

    [Fact]
    public void WriteRead_IncrementalSmallWrites_RoundTrips()
    {
        var key = GenerateKey();
        var memoryStream = new MemoryStream();

        using (var writer = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 32, leaveOpen: true))
        {
            for (int i = 0; i < 100; i++)
            {
                writer.Write(new byte[] { (byte)(i & 0xFF) }, 0, 1);
            }
        }

        memoryStream.Position = 0;
        using var reader = CyStream.CreateReader(memoryStream, key);
        var buffer = new byte[1024];
        var totalRead = 0;
        int read;
        while ((read = reader.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
            totalRead += read;

        totalRead.Should().Be(100);
        for (int i = 0; i < 100; i++)
            buffer[i].Should().Be((byte)(i & 0xFF));
    }

    [Fact]
    public void LeaveOpen_False_ClosesInnerStream()
    {
        var key = GenerateKey();
        var ms = new MemoryStream();

        using (var writer = CyStream.CreateWriter(ms, key, Guid.NewGuid(), leaveOpen: false))
        {
            writer.Write("test"u8.ToArray(), 0, 4);
        }

        var act = () => ms.Position = 0;
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void LeaveOpen_True_KeepsInnerStreamOpen()
    {
        var key = GenerateKey();
        var ms = new MemoryStream();

        using (var writer = CyStream.CreateWriter(ms, key, Guid.NewGuid(), leaveOpen: true))
        {
            writer.Write("test"u8.ToArray(), 0, 4);
        }

        // Should not throw
        ms.Position = 0;
        ms.Length.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Read_TruncatedStream_Throws()
    {
        var key = GenerateKey();
        var ms = new MemoryStream();

        using (var writer = CyStream.CreateWriter(ms, key, Guid.NewGuid(), 64, leaveOpen: true))
        {
            writer.Write(new byte[128], 0, 128);
        }

        // Truncate the stream to corrupt it
        var fullData = ms.ToArray();
        var truncated = new MemoryStream(fullData[..(fullData.Length / 2)]);

        using var reader = CyStream.CreateReader(truncated, key);
        var buffer = new byte[256];

        // Reading a truncated stream should eventually fail
        var act = () =>
        {
            var total = 0;
            int r;
            while ((r = reader.Read(buffer, total, buffer.Length - total)) > 0)
                total += r;
        };
        act.Should().Throw<Exception>();
    }
}
