using System.Security.Cryptography;
using CyTypes.Primitives;
using CyTypes.Streams.File;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class CyStreamWriterReaderTests : IDisposable
{
    private readonly string _tempDir;

    public CyStreamWriterReaderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "CyWriterReaderTests_" + Guid.NewGuid().ToString("N")[..8]);
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
    public void WriteRead_CyInt_RoundTrip()
    {
        var key = GenerateKey();
        var memoryStream = new MemoryStream();

        // Write CyInt(42)
        using (var cyStream = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 64, leaveOpen: true))
        {
            var writer = new CyStreamWriter(cyStream, leaveOpen: true);
            var value = new CyInt(42);
            writer.WriteValue(value);
            writer.Complete();
            writer.Dispose();
        }

        // Read back
        memoryStream.Position = 0;
        using var readerStream = CyStream.CreateReader(memoryStream, key);
        var reader = new CyStreamReader(readerStream);
        var result = reader.ReadNext();

        result.Should().NotBeNull();
        result!.Value.TypeId.Should().Be(CyTypeIds.CyInt);
        result.Value.EncryptedPayload.Should().NotBeEmpty();

        // No more values
        reader.ReadNext().Should().BeNull();
    }

    [Fact]
    public void WriteRead_MultipleCyTypes_RoundTrip()
    {
        var key = GenerateKey();
        var memoryStream = new MemoryStream();

        // Write CyInt(42) + CyString("secret") + CyBool(true)
        using (var cyStream = CyStream.CreateWriter(memoryStream, key, Guid.NewGuid(), 256, leaveOpen: true))
        {
            var writer = new CyStreamWriter(cyStream, leaveOpen: true);
            writer.WriteValue(new CyInt(42));
            writer.WriteValue(new CyString("secret"));
            writer.WriteValue(new CyBool(true));
            writer.Complete();
            writer.Dispose();
        }

        // Read back all values
        memoryStream.Position = 0;
        using var readerStream = CyStream.CreateReader(memoryStream, key);
        var reader = new CyStreamReader(readerStream);
        var values = reader.ReadAll().ToList();

        values.Should().HaveCount(3);

        values[0].TypeId.Should().Be(CyTypeIds.CyInt);
        values[0].EncryptedPayload.Should().NotBeEmpty();

        values[1].TypeId.Should().Be(CyTypeIds.CyString);
        values[1].EncryptedPayload.Should().NotBeEmpty();

        values[2].TypeId.Should().Be(CyTypeIds.CyBool);
        values[2].EncryptedPayload.Should().NotBeEmpty();
    }

    [Fact]
    public void WriteRead_CyTypes_ToFile()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "typed_stream.cys");

        // Write CyInt + CyString to file via CyFileStream
        using (var fileStream = CyFileStream.CreateWrite(filePath, key))
        {
            var writer = new CyStreamWriter(fileStream.Stream, leaveOpen: true);
            writer.WriteValue(new CyInt(42));
            writer.WriteValue(new CyString("hello"));
            writer.Complete();
            writer.Dispose();
        }

        System.IO.File.Exists(filePath).Should().BeTrue();

        // Read back via CyFileStream
        using var readFs = CyFileStream.OpenRead(filePath, key);
        var reader = new CyStreamReader(readFs.Stream);
        var values = reader.ReadAll().ToList();

        values.Should().HaveCount(2);
        values[0].TypeId.Should().Be(CyTypeIds.CyInt);
        values[0].EncryptedPayload.Should().NotBeEmpty();
        values[1].TypeId.Should().Be(CyTypeIds.CyString);
        values[1].EncryptedPayload.Should().NotBeEmpty();
    }
}
