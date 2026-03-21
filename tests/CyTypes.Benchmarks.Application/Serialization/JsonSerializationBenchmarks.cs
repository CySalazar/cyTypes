using System.Text.Json;
using BenchmarkDotNet.Attributes;
using CyTypes.Primitives;
using CyTypes.Primitives.Serialization;

namespace CyTypes.Benchmarks.Application.Serialization;

[MemoryDiagnoser]
public class JsonSerializationBenchmarks
{
    private JsonSerializerOptions _cyOptions = null!;
    private string _singleCyJson = null!;
    private string _singleNativeJson = null!;

    [GlobalSetup]
    public void Setup()
    {
        _cyOptions = new JsonSerializerOptions();
        _cyOptions.AddCyTypesConverters();

        var singleCy = new CyPayload { Name = new CyString("Test"), Value = new CyInt(42) };
        _singleCyJson = JsonSerializer.Serialize(singleCy, _cyOptions);

        var singleNative = new NativePayload { Name = "Test", Value = 42 };
        _singleNativeJson = JsonSerializer.Serialize(singleNative);
    }

    [Benchmark]
    public string Serialize_Single_CyTypes()
    {
        var obj = new CyPayload { Name = new CyString("Test"), Value = new CyInt(42) };
        return JsonSerializer.Serialize(obj, _cyOptions);
    }

    [Benchmark(Baseline = true)]
    public string Serialize_Single_Native()
    {
        var obj = new NativePayload { Name = "Test", Value = 42 };
        return JsonSerializer.Serialize(obj);
    }

    [Benchmark]
    public CyPayload? Deserialize_Single_CyTypes() =>
        JsonSerializer.Deserialize<CyPayload>(_singleCyJson, _cyOptions);

    [Benchmark]
    public NativePayload? Deserialize_Single_Native() =>
        JsonSerializer.Deserialize<NativePayload>(_singleNativeJson);

    [Benchmark]
    public string Serialize_Batch100_CyTypes()
    {
        var batch = Enumerable.Range(0, 100)
            .Select(i => new CyPayload { Name = new CyString($"Item{i}"), Value = new CyInt(i) })
            .ToList();
        return JsonSerializer.Serialize(batch, _cyOptions);
    }

    [Benchmark]
    public string Serialize_Batch100_Native()
    {
        var batch = Enumerable.Range(0, 100)
            .Select(i => new NativePayload { Name = $"Item{i}", Value = i })
            .ToList();
        return JsonSerializer.Serialize(batch);
    }
}

public class CyPayload
{
    public CyString Name { get; set; } = null!;
    public CyInt Value { get; set; } = null!;
}

public class NativePayload
{
    public string Name { get; set; } = string.Empty;
    public int Value { get; set; }
}
