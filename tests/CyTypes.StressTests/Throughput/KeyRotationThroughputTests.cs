using System.Diagnostics;
using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Throughput;

[Trait("Category", "Stress"), Trait("SubCategory", "Throughput")]
public class KeyRotationThroughputTests
{
    private readonly ITestOutputHelper _output;

    public KeyRotationThroughputTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task HighFrequency_KeyRotation_MeasureThroughput()
    {
        // Arrange
        const int rotationCount = 1000;
        using var keyManager = new KeyManager();
        var keyIds = new HashSet<Guid> { keyManager.KeyId };
        var counter = new ThroughputCounter();

        // Act
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < rotationCount; i++)
        {
            keyManager.RotateKey();
            keyIds.Add(keyManager.KeyId);
            counter.Increment();
        }
        sw.Stop();

        // Assert
        keyIds.Should().HaveCount(rotationCount + 1, "each rotation must produce a distinct KeyId (plus the initial)");

        var rotationsPerSec = rotationCount / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"Rotations: {rotationCount} in {sw.Elapsed.TotalSeconds:F2}s ({rotationsPerSec:N0} rotations/s)");
        _output.WriteLine(counter.Summary);

        await Task.CompletedTask;
    }

    [Fact]
    public async Task RotateAndReEncrypt_Soak()
    {
        // Arrange
        var duration = StressTestConfig.SoakDuration;
        var policy = SecurityPolicy.Performance;
        const int originalValue = 42;
        using var cyInt = new CyInt(originalValue, policy);
        var counter = new ThroughputCounter();

        // Act
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < duration)
        {
            cyInt.RotateKeyAndReEncrypt();
            var decrypted = cyInt.ToInsecureInt();
            decrypted.Should().Be(originalValue, "value must be preserved after rotation");
            counter.Increment();
        }

        // Assert
        _output.WriteLine($"RotateAndReEncrypt soak: {counter.Summary}");
        counter.Count.Should().BeGreaterThan(0, "should complete at least some rotations");

        await Task.CompletedTask;
    }
}
