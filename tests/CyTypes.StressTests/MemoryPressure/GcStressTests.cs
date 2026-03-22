using CyTypes.Core.Memory;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.MemoryPressure;

[Trait("Category", "Stress")]
[Trait("SubCategory", "MemoryPressure")]
public class GcStressTests
{
    private readonly ITestOutputHelper _output;

    public GcStressTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task ForceGC_DuringEncryption_NoCorruption()
    {
        // Arrange
        const int iterations = 1000;
        var policy = SecurityPolicy.Performance;
        using var cts = new CancellationTokenSource();
        var counter = new ThroughputCounter();

        // Background task: force aggressive GC continuously
        var gcTask = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                GC.Collect(2, GCCollectionMode.Forced, blocking: false);
                await Task.Delay(1, cts.Token).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            }
        });

        // Act — foreground: encrypt/decrypt cycles
        var errors = new List<string>();
        for (var i = 0; i < iterations; i++)
        {
            var value = i;
            using var cyInt = new CyInt(value, policy);
            var decrypted = cyInt.ToInsecureInt();

            if (decrypted != value)
            {
                errors.Add($"Iteration {i}: expected {value}, got {decrypted}");
            }

            counter.Increment();
        }

        // Stop GC background task
        await cts.CancelAsync();
        await gcTask;

        _output.WriteLine($"Completed {counter.Summary}");
        _output.WriteLine($"Errors: {errors.Count}");

        // Assert
        errors.Should().BeEmpty("all encrypt/decrypt cycles should return correct values despite aggressive GC");
    }

    [Fact]
    public void Finalizer_Race_WithExplicitDispose()
    {
        // Arrange — create 1000 SecureBuffers, some explicitly disposed, some left for finalizer
        const int count = 1000;

        // Act — should not crash or throw
        var action = () =>
        {
            for (var i = 0; i < count; i++)
            {
                var buf = new SecureBuffer(64);
                buf.Write(new byte[64]);

                // Explicitly dispose every other one; let the rest be finalized
                if (i % 2 == 0)
                {
                    buf.Dispose();
                }
                // Odd-indexed buffers are abandoned — finalizer will handle them
            }

            // Force finalizers to run
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true);
        };

        // Assert — no crash, no exception
        action.Should().NotThrow("mixing explicit disposal with finalizer cleanup should be safe");

        _output.WriteLine($"Successfully created and finalized/disposed {count} SecureBuffers without crash");
    }

    [Fact]
    public void CyType_Fields_Survive_GC_During_Operator_Storm()
    {
        // Regression test: reproduces the exact scenario that caused 15 benchmark failures.
        // CyType operands stored as local variables must survive GC pressure from
        // thousands of intermediate operator results being created and discarded.
        var a = new CyInt(42, SecurityPolicy.Performance);
        var b = new CyInt(17, SecurityPolicy.Performance);

        for (var i = 0; i < 10_000; i++)
        {
            var result = a + b; // Intermediate — eligible for GC immediately
            result.ToInsecureInt().Should().Be(59);
            result.Dispose();

            if (i % 1000 == 0)
                GC.Collect(2, GCCollectionMode.Forced, blocking: false);
        }

        // Original operands MUST survive
        a.ToInsecureInt().Should().Be(42, "operand 'a' must not be disposed by GC");
        b.ToInsecureInt().Should().Be(17, "operand 'b' must not be disposed by GC");

        a.Dispose();
        b.Dispose();

        _output.WriteLine("CyType fields survived 10,000 operator iterations with GC pressure");
    }
}
