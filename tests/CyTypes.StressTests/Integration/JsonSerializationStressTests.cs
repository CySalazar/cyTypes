using System.Collections.Concurrent;
using System.Text.Json;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.Primitives.Serialization;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Integration;

[Trait("Category", "Stress"), Trait("SubCategory", "Integration")]
public class JsonSerializationStressTests
{
    private readonly ITestOutputHelper _output;
    private readonly JsonSerializerOptions _jsonOptions;

    public JsonSerializationStressTests(ITestOutputHelper output)
    {
        _output = output;
        _jsonOptions = new JsonSerializerOptions();
        _jsonOptions.AddCyTypesConverters();
    }

    [Fact]
    public async Task SerializeDeserialize_AllTypes_Bulk()
    {
        // Arrange
        const int count = 100;
        var policy = SecurityPolicy.Performance;
        var metrics = new StressTestMetrics();
        var rng = new Random(42);

        // Act & Assert: CyInt
        for (var i = 0; i < count; i++)
        {
            var val = rng.Next();
            using var original = new CyInt(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyInt>(json, _jsonOptions)!;
            deserialized.ToInsecureInt().Should().Be(val);
            metrics.IncrementCounter("CyInt");
        }

        // CyString
        for (var i = 0; i < count; i++)
        {
            var val = $"test-string-{rng.Next()}";
            using var original = new CyString(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyString>(json, _jsonOptions)!;
            deserialized.ToInsecureString().Should().Be(val);
            metrics.IncrementCounter("CyString");
        }

        // CyBool
        for (var i = 0; i < count; i++)
        {
            var val = rng.Next(2) == 1;
            using var original = new CyBool(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyBool>(json, _jsonOptions)!;
            deserialized.ToInsecureBool().Should().Be(val);
            metrics.IncrementCounter("CyBool");
        }

        // CyDouble
        for (var i = 0; i < count; i++)
        {
            var val = rng.NextDouble() * 1000;
            using var original = new CyDouble(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyDouble>(json, _jsonOptions)!;
            deserialized.ToInsecureDouble().Should().Be(val);
            metrics.IncrementCounter("CyDouble");
        }

        // CyFloat
        for (var i = 0; i < count; i++)
        {
            var val = (float)(rng.NextDouble() * 1000);
            using var original = new CyFloat(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyFloat>(json, _jsonOptions)!;
            deserialized.ToInsecureFloat().Should().Be(val);
            metrics.IncrementCounter("CyFloat");
        }

        // CyLong
        for (var i = 0; i < count; i++)
        {
            var val = rng.NextInt64();
            using var original = new CyLong(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyLong>(json, _jsonOptions)!;
            deserialized.ToInsecureLong().Should().Be(val);
            metrics.IncrementCounter("CyLong");
        }

        // CyDecimal
        for (var i = 0; i < count; i++)
        {
            var val = (decimal)(rng.NextDouble() * 1000);
            using var original = new CyDecimal(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyDecimal>(json, _jsonOptions)!;
            deserialized.ToInsecureDecimal().Should().Be(val);
            metrics.IncrementCounter("CyDecimal");
        }

        // CyGuid
        for (var i = 0; i < count; i++)
        {
            var val = Guid.NewGuid();
            using var original = new CyGuid(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyGuid>(json, _jsonOptions)!;
            deserialized.ToInsecureGuid().Should().Be(val);
            metrics.IncrementCounter("CyGuid");
        }

        // CyDateTime
        for (var i = 0; i < count; i++)
        {
            var val = DateTime.UtcNow.AddSeconds(-rng.Next(100000));
            using var original = new CyDateTime(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyDateTime>(json, _jsonOptions)!;
            deserialized.ToInsecureDateTime().Should().Be(val);
            metrics.IncrementCounter("CyDateTime");
        }

        // CyBytes
        for (var i = 0; i < count; i++)
        {
            var val = new byte[rng.Next(1, 256)];
            rng.NextBytes(val);
            using var original = new CyBytes(val, policy);
            var json = JsonSerializer.Serialize(original, _jsonOptions);
            using var deserialized = JsonSerializer.Deserialize<CyBytes>(json, _jsonOptions)!;
            deserialized.ToInsecureBytes().Should().BeEquivalentTo(val);
            metrics.IncrementCounter("CyBytes");
        }

        _output.WriteLine(metrics.GetSummary());

        await Task.CompletedTask;
    }

    [Fact]
    public async Task Concurrent_JsonRoundTrip()
    {
        // Arrange
        var threadCount = StressTestConfig.ConcurrentThreads;
        const int opsPerThread = 100;
        var policy = SecurityPolicy.Performance;
        var exceptions = new ConcurrentBag<Exception>();
        var barrier = new Barrier(threadCount);
        var counter = new ThroughputCounter();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(threadId => Task.Run(() =>
        {
            // Each thread gets its own JsonSerializerOptions to avoid contention
            var opts = new JsonSerializerOptions();
            opts.AddCyTypesConverters();

            barrier.SignalAndWait();
            try
            {
                for (var i = 0; i < opsPerThread; i++)
                {
                    var value = threadId * 10000 + i;
                    using var original = new CyInt(value, policy);
                    var json = JsonSerializer.Serialize(original, opts);
                    using var deserialized = JsonSerializer.Deserialize<CyInt>(json, opts)!;
                    var result = deserialized.ToInsecureInt();

                    if (result != value)
                        throw new InvalidOperationException(
                            $"Round-trip mismatch: expected {value}, got {result}");

                    counter.Increment();
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("concurrent JSON round-trips must not corrupt data");
        counter.Count.Should().Be(threadCount * opsPerThread);

        _output.WriteLine($"Concurrent JSON round-trip: {counter.Summary}");
    }
}
