using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.MemoryPressure;

[Trait("Category", "Stress")]
[Trait("SubCategory", "MemoryPressure")]
public class LargePayloadTests
{
    private readonly ITestOutputHelper _output;

    public LargePayloadTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void CyBytes_NearMaxSize_16MB()
    {
        // Arrange
        const int size = 16 * 1024 * 1024; // 16 MB
        var data = new byte[size];
        Random.Shared.NextBytes(data);
        var policy = SecurityPolicy.Performance;

        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));

        // Act
        using var cyBytes = new CyBytes(data, policy);
        var decrypted = cyBytes.ToInsecureBytes();

        var afterRoundTrip = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After round-trip", afterRoundTrip));
        _output.WriteLine($"Memory used: {MemoryTracker.MemoryDelta(baseline, afterRoundTrip) / 1024.0 / 1024.0:F2} MB");

        // Assert
        decrypted.Should().Equal(data, "16 MB CyBytes should round-trip correctly");
    }

    [Fact]
    public void CyString_LargeString_1MB()
    {
        // Arrange — 1 MB of characters
        const int charCount = 1024 * 1024;
        var largeString = new string('A', charCount);
        var policy = SecurityPolicy.Performance;

        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));

        // Act
        using var cyString = new CyString(largeString, policy);
        var decrypted = cyString.ToInsecureString();

        var afterRoundTrip = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After round-trip", afterRoundTrip));

        // Assert
        decrypted.Should().Be(largeString, "1 MB CyString should round-trip correctly");
    }

    [Fact]
    public void AesGcmEngine_MaxPayload()
    {
        // Arrange
        const int size = 16 * 1024 * 1024; // 16 MB
        var plaintext = new byte[size];
        Random.Shared.NextBytes(plaintext);

        var key = new byte[32]; // 256-bit key
        RandomNumberGenerator.Fill(key);

        var engine = new AesGcmEngine();
        var counter = new ThroughputCounter();

        var baseline = MemoryTracker.TakeSnapshot(forceGc: true);
        _output.WriteLine(MemoryTracker.FormatSnapshot("Baseline", baseline));

        // Act
        counter.Reset();
        var ciphertext = engine.Encrypt(plaintext, key);
        counter.Increment();
        _output.WriteLine($"Encrypt: {counter.Elapsed.TotalMilliseconds:F2} ms for {size / 1024.0 / 1024.0:F0} MB");

        counter.Reset();
        var decrypted = engine.Decrypt(ciphertext, key);
        counter.Increment();
        _output.WriteLine($"Decrypt: {counter.Elapsed.TotalMilliseconds:F2} ms for {size / 1024.0 / 1024.0:F0} MB");

        var afterRoundTrip = MemoryTracker.TakeSnapshot(forceGc: false);
        _output.WriteLine(MemoryTracker.FormatSnapshot("After round-trip", afterRoundTrip));

        // Assert
        decrypted.Should().Equal(plaintext, "AES-GCM 16 MB round-trip should produce identical plaintext");
    }
}
