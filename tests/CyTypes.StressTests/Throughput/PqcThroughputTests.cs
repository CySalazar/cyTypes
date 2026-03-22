using System.Diagnostics;
using CyTypes.Core.Crypto.Pqc;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Throughput;

[Trait("Category", "Stress"), Trait("SubCategory", "Throughput")]
public class PqcThroughputTests
{
    private readonly ITestOutputHelper _output;

    public PqcThroughputTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task MlKem1024_KeyGen_Throughput()
    {
        // Arrange
        const int iterations = 100;
        var pqc = new MlKemKeyEncapsulation();
        var counter = new ThroughputCounter();

        // Act
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < iterations; i++)
        {
            var (publicKey, secretKey) = pqc.GenerateKeyPair();
            publicKey.Should().NotBeEmpty("public key must be generated");
            secretKey.Should().NotBeEmpty("secret key must be generated");
            counter.Increment();
        }
        sw.Stop();

        // Assert
        var pairsPerSec = iterations / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"ML-KEM-1024 key generation: {iterations} pairs in {sw.Elapsed.TotalSeconds:F2}s ({pairsPerSec:F1} pairs/s)");
        _output.WriteLine(counter.Summary);

        counter.Count.Should().Be(iterations);

        await Task.CompletedTask;
    }

    [Fact]
    public async Task MlKem1024_Encapsulate_Decapsulate_Throughput()
    {
        // Arrange
        const int iterations = 100;
        var pqc = new MlKemKeyEncapsulation();
        var (publicKey, secretKey) = pqc.GenerateKeyPair();
        var counter = new ThroughputCounter();
        var metrics = new StressTestMetrics();

        // Act
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < iterations; i++)
        {
            var encapSw = Stopwatch.StartNew();
            var (ciphertext, sharedSecretSender) = pqc.Encapsulate(publicKey);
            encapSw.Stop();
            metrics.RecordLatency("encapsulate", encapSw.Elapsed);

            var decapSw = Stopwatch.StartNew();
            var sharedSecretReceiver = pqc.Decapsulate(ciphertext, secretKey);
            decapSw.Stop();
            metrics.RecordLatency("decapsulate", decapSw.Elapsed);

            // Assert: shared secrets must match
            sharedSecretSender.Should().BeEquivalentTo(sharedSecretReceiver,
                $"shared secrets must match on iteration {i}");

            counter.Increment();
        }
        sw.Stop();

        // Output
        var cyclesPerSec = iterations / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"ML-KEM-1024 encapsulate+decapsulate: {iterations} cycles in {sw.Elapsed.TotalSeconds:F2}s ({cyclesPerSec:F1} cycles/s)");
        _output.WriteLine(metrics.GetSummary());

        counter.Count.Should().Be(iterations);

        await Task.CompletedTask;
    }
}
