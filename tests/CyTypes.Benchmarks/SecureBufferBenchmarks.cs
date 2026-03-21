using BenchmarkDotNet.Attributes;
using CyTypes.Core.Memory;

namespace CyTypes.Benchmarks;

[MemoryDiagnoser]
public class SecureBufferBenchmarks
{
    private byte[] _data = null!;

    [Params(32, 256, 1024, 4096)]
    public int BufferSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[BufferSize];
        Array.Fill(_data, (byte)0xAA);
    }

    [Benchmark]
    public void AllocateAndDispose()
    {
        using var buffer = new SecureBuffer(BufferSize);
    }

    [Benchmark]
    public void WriteAndRead()
    {
        using var buffer = new SecureBuffer(BufferSize);
        buffer.Write(_data);
        _ = buffer.ToArray();
    }

    [Benchmark(Baseline = true)]
    public void AllocateVsRegularArray()
    {
        var arr = new byte[BufferSize];
        _data.CopyTo(arr, 0);
        _ = arr.ToArray();
    }
}
