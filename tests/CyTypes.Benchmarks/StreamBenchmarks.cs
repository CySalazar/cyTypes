using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using CyTypes.Benchmarks.Config;
using CyTypes.Core.Crypto;
using CyTypes.Streams;
using CyTypes.Streams.File;

namespace CyTypes.Benchmarks;

[Config(typeof(ThroughputConfig))]
[MemoryDiagnoser]
public class ChunkedCryptoEngineBenchmarks : IDisposable
{
    private ChunkedCryptoEngine _engine = null!;
    private byte[] _plaintext = null!;
    private byte[] _encrypted = null!;

    [Params(1024, 4096, 65536, 262144)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        _engine = new ChunkedCryptoEngine(key, PayloadSize);
        _plaintext = new byte[PayloadSize];
        RandomNumberGenerator.Fill(_plaintext);
        _encrypted = _engine.EncryptChunk(_plaintext, 0, isFinal: true);
    }

    [GlobalCleanup]
    public void Cleanup() => _engine.Dispose();

    public void Dispose()
    {
        _engine?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Benchmark]
    public byte[] EncryptChunk() => _engine.EncryptChunk(_plaintext, 0, isFinal: true);

    [Benchmark]
    public byte[] DecryptChunk() => _engine.DecryptChunk(_encrypted, 0, out _);
}

[Config(typeof(ThroughputConfig))]
[MemoryDiagnoser]
public class CyStreamBenchmarks
{
    private byte[] _key = null!;
    private byte[] _data = null!;

    [Params(1024, 4096, 65536, 262144)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
        _data = new byte[PayloadSize];
        RandomNumberGenerator.Fill(_data);
    }

    [Benchmark]
    public void WriteReadRoundTrip()
    {
        var ms = new MemoryStream();

        using (var writer = CyStream.CreateWriter(ms, _key, Guid.NewGuid(), leaveOpen: true))
        {
            writer.Write(_data, 0, _data.Length);
        }

        ms.Position = 0;
        using var reader = CyStream.CreateReader(ms, _key);
        var buffer = new byte[PayloadSize + 256];
        var totalRead = 0;
        int read;
        while ((read = reader.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
        {
            totalRead += read;
        }
    }
}

[Config(typeof(ThroughputConfig))]
[MemoryDiagnoser]
public class CyFileStreamBenchmarks
{
    private byte[] _key = null!;
    private byte[] _data = null!;
    private string _tempDir = null!;
    private int _fileCounter;

    [Params(1024, 4096, 65536, 262144)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
        _data = new byte[PayloadSize];
        RandomNumberGenerator.Fill(_data);
        _tempDir = Path.Combine(Path.GetTempPath(), "CyBench_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    [Benchmark]
    public void WriteReadRoundTrip()
    {
        var filePath = Path.Combine(_tempDir, $"bench_{Interlocked.Increment(ref _fileCounter)}.cys");

        using (var fs = CyFileStream.CreateWrite(filePath, _key))
        {
            fs.Write(_data);
        }

        using var readFs = CyFileStream.OpenRead(filePath, _key);
        var buffer = new byte[PayloadSize + 256];
        readFs.Read(buffer);

        System.IO.File.Delete(filePath);
    }
}
