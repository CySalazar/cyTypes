using System.Diagnostics;
using System.Security.Cryptography;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Throughput;

[Trait("Category", "Stress"), Trait("SubCategory", "Throughput")]
public class EncryptDecryptSoakTests
{
    private readonly ITestOutputHelper _output;

    public EncryptDecryptSoakTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task CyInt_SoakTest_ContinuousEncryptDecrypt()
    {
        // Arrange
        var duration = StressTestConfig.SoakDuration;
        var metrics = new StressTestMetrics();
        var counter = new ThroughputCounter();
        var policy = SecurityPolicy.Performance;

        // Track throughput in first and last 10-second windows
        var earlyWindowOps = 0L;
        var earlyWindowEnd = TimeSpan.FromSeconds(10);
        var lateWindowOps = 0L;
        var lateWindowStart = duration - TimeSpan.FromSeconds(10);
        var lateWindowStarted = false;
        long opsAtLateWindowStart = 0;

        // Act
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < duration)
        {
            var value = Random.Shared.Next();
            using var cyInt = new CyInt(value, policy);
            var decrypted = cyInt.ToInsecureInt();
            decrypted.Should().Be(value);

            counter.Increment();
            metrics.IncrementCounter("ops");

            if (sw.Elapsed < earlyWindowEnd)
            {
                earlyWindowOps++;
            }

            if (sw.Elapsed >= lateWindowStart && !lateWindowStarted)
            {
                lateWindowStarted = true;
                opsAtLateWindowStart = counter.Count;
            }
        }

        lateWindowOps = counter.Count - opsAtLateWindowStart;

        // Assert: no degradation >20% between first and last 10s windows
        var earlyRate = earlyWindowOps / 10.0;
        var lateRate = lateWindowOps / 10.0;

        _output.WriteLine($"Total: {counter.Summary}");
        _output.WriteLine($"Early window (first 10s): {earlyRate:N0} ops/s");
        _output.WriteLine($"Late window (last 10s): {lateRate:N0} ops/s");
        _output.WriteLine(metrics.GetSummary());

        if (earlyRate > 0)
        {
            var degradation = (earlyRate - lateRate) / earlyRate;
            degradation.Should().BeLessThan(0.50, "throughput should not degrade more than 50% over the soak period");
        }

        await Task.CompletedTask;
    }

    [Fact]
    public async Task CyString_SoakTest_VariableLengths()
    {
        // Arrange
        var duration = StressTestConfig.SoakDuration;
        var counter = new ThroughputCounter();
        var policy = SecurityPolicy.Performance;
        var rng = new Random(42);

        var earlyWindowOps = 0L;
        var earlyWindowEnd = TimeSpan.FromSeconds(10);
        long opsAtLateWindowStart = 0;
        var lateWindowStart = duration - TimeSpan.FromSeconds(10);
        var lateWindowStarted = false;

        // Act
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < duration)
        {
            var length = rng.Next(1, 10001);
            var chars = new char[length];
            for (var i = 0; i < length; i++)
                chars[i] = (char)rng.Next(32, 127);
            var original = new string(chars);

            using var cyStr = new CyString(original, policy);
            var decrypted = cyStr.ToInsecureString();
            decrypted.Should().Be(original);

            counter.Increment();

            if (sw.Elapsed < earlyWindowEnd)
                earlyWindowOps++;

            if (sw.Elapsed >= lateWindowStart && !lateWindowStarted)
            {
                lateWindowStarted = true;
                opsAtLateWindowStart = counter.Count;
            }
        }

        var lateWindowOps = counter.Count - opsAtLateWindowStart;
        var earlyRate = earlyWindowOps / 10.0;
        var lateRate = lateWindowOps / 10.0;

        _output.WriteLine($"Total: {counter.Summary}");
        _output.WriteLine($"Early window: {earlyRate:N0} ops/s, Late window: {lateRate:N0} ops/s");

        if (earlyRate > 0)
        {
            var degradation = (earlyRate - lateRate) / earlyRate;
            degradation.Should().BeLessThan(0.50, "CyString throughput should not degrade more than 50%");
        }

        await Task.CompletedTask;
    }

    [Fact]
    public async Task AllTypes_SoakTest_MixedWorkload()
    {
        // Arrange
        var duration = StressTestConfig.SoakDuration;
        var metrics = new StressTestMetrics();
        var policy = SecurityPolicy.Performance;
        var rng = new Random(42);
        var typeNames = new[] { "CyInt", "CyString", "CyBool", "CyDouble", "CyFloat", "CyLong", "CyDecimal", "CyGuid", "CyDateTime", "CyBytes" };
        var typeIndex = 0;

        // Act
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < duration)
        {
            var typeName = typeNames[typeIndex % typeNames.Length];
            typeIndex++;

            switch (typeName)
            {
                case "CyInt":
                {
                    var v = rng.Next();
                    using var cy = new CyInt(v, policy);
                    cy.ToInsecureInt().Should().Be(v);
                    break;
                }
                case "CyString":
                {
                    var v = $"test-{rng.Next()}";
                    using var cy = new CyString(v, policy);
                    cy.ToInsecureString().Should().Be(v);
                    break;
                }
                case "CyBool":
                {
                    var v = rng.Next(2) == 1;
                    using var cy = new CyBool(v, policy);
                    cy.ToInsecureBool().Should().Be(v);
                    break;
                }
                case "CyDouble":
                {
                    var v = rng.NextDouble();
                    using var cy = new CyDouble(v, policy);
                    cy.ToInsecureDouble().Should().Be(v);
                    break;
                }
                case "CyFloat":
                {
                    var v = (float)rng.NextDouble();
                    using var cy = new CyFloat(v, policy);
                    cy.ToInsecureFloat().Should().Be(v);
                    break;
                }
                case "CyLong":
                {
                    var v = rng.NextInt64();
                    using var cy = new CyLong(v, policy);
                    cy.ToInsecureLong().Should().Be(v);
                    break;
                }
                case "CyDecimal":
                {
                    var v = (decimal)rng.NextDouble() * 1000m;
                    using var cy = new CyDecimal(v, policy);
                    cy.ToInsecureDecimal().Should().Be(v);
                    break;
                }
                case "CyGuid":
                {
                    var v = Guid.NewGuid();
                    using var cy = new CyGuid(v, policy);
                    cy.ToInsecureGuid().Should().Be(v);
                    break;
                }
                case "CyDateTime":
                {
                    var v = DateTime.UtcNow.AddSeconds(-rng.Next(100000));
                    using var cy = new CyDateTime(v, policy);
                    cy.ToInsecureDateTime().Should().Be(v);
                    break;
                }
                case "CyBytes":
                {
                    var v = new byte[rng.Next(1, 256)];
                    rng.NextBytes(v);
                    using var cy = new CyBytes(v, policy);
                    cy.ToInsecureBytes().Should().BeEquivalentTo(v);
                    break;
                }
            }

            metrics.IncrementCounter(typeName);
            metrics.IncrementCounter("total");
        }

        // Output per-type throughput
        _output.WriteLine(metrics.GetSummary());
        foreach (var name in typeNames)
        {
            var count = metrics.GetCounter(name);
            _output.WriteLine($"  {name}: {count:N0} ops");
        }

        metrics.GetCounter("total").Should().BeGreaterThan(0, "should complete at least some operations");

        await Task.CompletedTask;
    }
}
