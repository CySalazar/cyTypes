using System.Security.Cryptography;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Integration;

/// <summary>
/// Tests thread-safety of CyTypes under concurrent access.
/// Verifies that encryption/decryption, taint tracking, and counters
/// behave correctly under multi-threaded workloads.
/// </summary>
public sealed class ConcurrencyTests
{
    private const int ThreadCount = 8;
    private const int IterationsPerThread = 50;

    [Fact]
    public void Concurrent_creation_and_decryption_of_CyInt()
    {
        var results = new int[ThreadCount * IterationsPerThread];
        var exceptions = new List<Exception>();

        Parallel.For(0, ThreadCount, threadIdx =>
        {
            for (int i = 0; i < IterationsPerThread; i++)
            {
                try
                {
                    var value = threadIdx * IterationsPerThread + i;
                    using var cy = new CyInt(value);
                    results[value] = cy.ToInsecureInt();
                }
                catch (Exception ex)
                {
                    lock (exceptions)
                        exceptions.Add(ex);
                }
            }
        });

        exceptions.Should().BeEmpty("no exceptions should occur during concurrent CyInt operations");

        // Verify every value roundtripped correctly
        for (int i = 0; i < results.Length; i++)
            results[i].Should().Be(i);
    }

    [Fact]
    public void Concurrent_creation_and_decryption_of_CyString()
    {
        var results = new string[ThreadCount * IterationsPerThread];
        var exceptions = new List<Exception>();

        Parallel.For(0, ThreadCount, threadIdx =>
        {
            for (int i = 0; i < IterationsPerThread; i++)
            {
                try
                {
                    var idx = threadIdx * IterationsPerThread + i;
                    var value = $"thread-{threadIdx}-iter-{i}";
                    using var cy = new CyString(value);
                    results[idx] = cy.ToInsecureString();
                }
                catch (Exception ex)
                {
                    lock (exceptions)
                        exceptions.Add(ex);
                }
            }
        });

        exceptions.Should().BeEmpty("no exceptions should occur during concurrent CyString operations");

        // Verify all values are present and correct
        results.Should().OnlyContain(s => s != null);
        results.Distinct().Should().HaveCount(ThreadCount * IterationsPerThread);
    }

    [Fact]
    public void Concurrent_arithmetic_produces_correct_results()
    {
        var results = new int[ThreadCount];
        var exceptions = new List<Exception>();

        Parallel.For(0, ThreadCount, threadIdx =>
        {
            try
            {
                // Each thread computes sum 1..10 = 55
                using var acc = new CyInt(0);
                var sum = acc;
                var intermediates = new List<CyInt> { acc };

                for (int i = 1; i <= 10; i++)
                {
                    var next = sum + new CyInt(i);
                    intermediates.Add(next);
                    sum = next;
                }

                results[threadIdx] = sum.ToInsecureInt();

                foreach (var cy in intermediates)
                    cy.Dispose();
            }
            catch (Exception ex)
            {
                lock (exceptions)
                    exceptions.Add(ex);
            }
        });

        exceptions.Should().BeEmpty();
        results.Should().AllBeEquivalentTo(55);
    }

    [Fact]
    public void Concurrent_reads_of_shared_instance_all_succeed()
    {
        using var shared = new CyInt(42, SecurityPolicy.Performance); // unlimited decryptions
        var results = new int[ThreadCount * IterationsPerThread];
        var exceptions = new List<Exception>();

        Parallel.For(0, ThreadCount * IterationsPerThread, i =>
        {
            try
            {
                results[i] = shared.ToInsecureInt();
            }
            catch (Exception ex)
            {
                lock (exceptions)
                    exceptions.Add(ex);
            }
        });

        exceptions.Should().BeEmpty();
        results.Should().AllBeEquivalentTo(42);
    }

    [Fact]
    public async Task Concurrent_taint_marking_is_visible_to_all_threads()
    {
        using var cy = new CyInt(42, SecurityPolicy.Performance);

        // Mark tainted from one thread
        await Task.Run(() => cy.MarkTainted());

        // All threads should see the taint
        var observations = new bool[ThreadCount];
        Parallel.For(0, ThreadCount, i =>
        {
            observations[i] = cy.IsTainted;
        });

        observations.Should().AllBeEquivalentTo(true);
    }

    [Fact]
    public void Concurrent_dispose_does_not_throw()
    {
        var cy = new CyInt(42);
        var exceptions = new List<Exception>();

        // Multiple threads try to dispose the same instance
        Parallel.For(0, ThreadCount, _ =>
        {
            try
            {
                cy.Dispose();
            }
            catch (Exception ex)
            {
                lock (exceptions)
                    exceptions.Add(ex);
            }
        });

        exceptions.Should().BeEmpty("concurrent Dispose calls should be safe");
        cy.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Concurrent_CyBool_operations()
    {
        var exceptions = new List<Exception>();

        Parallel.For(0, ThreadCount, _ =>
        {
            try
            {
                using var a = new CyBool(true);
                using var b = new CyBool(false);

                using var andResult = a & b;
                using var orResult = a | b;
                using var xorResult = a ^ b;

                andResult.ToInsecureBool().Should().BeFalse();
                orResult.ToInsecureBool().Should().BeTrue();
                xorResult.ToInsecureBool().Should().BeTrue();
            }
            catch (Exception ex)
            {
                lock (exceptions)
                    exceptions.Add(ex);
            }
        });

        exceptions.Should().BeEmpty();
    }

    [Fact]
    public void Concurrent_string_operations()
    {
        var exceptions = new List<Exception>();

        Parallel.For(0, ThreadCount, threadIdx =>
        {
            try
            {
                using var a = new CyString("Hello");
                using var b = new CyString(" World");
                using var concat = a + b;

                concat.ToInsecureString().Should().Be("Hello World");
                concat.Length.Should().Be(11);

                using var upper = concat.ToUpper();
                upper.ToInsecureString().Should().Be("HELLO WORLD");
            }
            catch (Exception ex)
            {
                lock (exceptions)
                    exceptions.Add(ex);
            }
        });

        exceptions.Should().BeEmpty();
    }

    [Fact]
    public void Auto_destroy_under_concurrent_decryptions()
    {
        var policy = new SecurityPolicyBuilder()
            .WithMaxDecryptionCount(10)
            .Build();

        var cy = new CyInt(42, policy);
        var successCount = 0;
        var disposedCount = 0;

        Parallel.For(0, 50, _ =>
        {
            try
            {
                _ = cy.ToInsecureInt();
                Interlocked.Increment(ref successCount);
            }
            catch (ObjectDisposedException)
            {
                Interlocked.Increment(ref disposedCount);
            }
            catch (AuthenticationTagMismatchException)
            {
                // Race condition: buffer zeroed by auto-destroy while decrypt was in-flight
                Interlocked.Increment(ref disposedCount);
            }
        });

        // At least some should succeed, and some should see disposed state
        cy.IsDisposed.Should().BeTrue();
        successCount.Should().BeGreaterThan(0);
        (successCount + disposedCount).Should().Be(50);
    }

    [Fact]
    public void Concurrent_policy_reads_are_consistent()
    {
        using var cy = new CyInt(42, SecurityPolicy.Balanced);
        var observations = new string[ThreadCount * IterationsPerThread];

        Parallel.For(0, ThreadCount * IterationsPerThread, i =>
        {
            observations[i] = cy.Policy.Name;
        });

        observations.Should().AllBeEquivalentTo("Balanced");
    }

    [Fact]
    public void Concurrent_mixed_types_no_cross_contamination()
    {
        var exceptions = new List<Exception>();

        Parallel.For(0, ThreadCount, threadIdx =>
        {
            try
            {
                using var cyInt = new CyInt(threadIdx);
                using var cyLong = new CyLong(threadIdx * 100L);
                using var cyDouble = new CyDouble(threadIdx * 1.5);
                using var cyString = new CyString($"thread-{threadIdx}");

                cyInt.ToInsecureInt().Should().Be(threadIdx);
                cyLong.ToInsecureValue().Should().Be(threadIdx * 100L);
                cyDouble.ToInsecureValue().Should().Be(threadIdx * 1.5);
                cyString.ToInsecureString().Should().Be($"thread-{threadIdx}");
            }
            catch (Exception ex)
            {
                lock (exceptions)
                    exceptions.Add(ex);
            }
        });

        exceptions.Should().BeEmpty();
    }
}
