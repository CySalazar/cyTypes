using System.Security.Cryptography;
using CyTypes.Streams.File;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class CyFileStreamTests : IDisposable
{
    private readonly string _tempDir;

    public CyFileStreamTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "CyFileStreamTests_" + Guid.NewGuid().ToString("N")[..8]);
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
    public void WriteRead_Key_RoundTrip()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "test.cys");
        var data = "Encrypted file content!"u8.ToArray();

        // Write
        using (var fs = CyFileStream.CreateWrite(filePath, key))
        {
            fs.Write(data);
        }

        System.IO.File.Exists(filePath).Should().BeTrue();

        // Read
        using var readFs = CyFileStream.OpenRead(filePath, key);
        var buffer = new byte[256];
        var read = readFs.Read(buffer);

        buffer.AsSpan(0, read).ToArray().Should().Equal(data);
    }

    [Fact]
    public void WriteRead_Passphrase_RoundTrip()
    {
        var filePath = Path.Combine(_tempDir, "passphrase.cys");
        var data = "Secret with passphrase!"u8.ToArray();

        using (var fs = CyFileStream.CreateWrite(filePath, "my-secure-passphrase"))
        {
            fs.Write(data);
        }

        using var readFs = CyFileStream.OpenRead(filePath, "my-secure-passphrase");
        var buffer = new byte[256];
        var read = readFs.Read(buffer);

        buffer.AsSpan(0, read).ToArray().Should().Equal(data);
    }

    [Fact]
    public void AtomicWrite_CreatesFileOnlyAfterClose()
    {
        var key = GenerateKey();
        var filePath = Path.Combine(_tempDir, "atomic.cys");

        using (var fs = CyFileStream.CreateWrite(filePath, key, new SecureFileOptions { AtomicWrite = true }))
        {
            fs.Write("data"u8.ToArray());
            // During write, file should not exist at final path yet
            System.IO.File.Exists(filePath).Should().BeFalse();
        }

        // After disposal, file should be at final path
        System.IO.File.Exists(filePath).Should().BeTrue();
    }

    [Fact]
    public void Read_WrongPassphrase_Throws()
    {
        var filePath = Path.Combine(_tempDir, "wrong_pass.cys");

        using (var fs = CyFileStream.CreateWrite(filePath, "correct-password"))
        {
            fs.Write("secret"u8.ToArray());
        }

        using var readFs = CyFileStream.OpenRead(filePath, "wrong-password");
        var buffer = new byte[256];

        var act = () => readFs.Read(buffer);
        act.Should().Throw<CryptographicException>();
    }
}
