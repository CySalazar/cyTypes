using System.Collections.Concurrent;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class CyPrimitiveConcurrencyTests
{
    [Fact]
    public async Task ConcurrentCyInt_EncryptDecrypt_SameInstance()
    {
        // Arrange: N threads all call ToInsecureInt on the same CyInt
        var threadCount = StressTestConfig.ConcurrentThreads;
        using var cyInt = new CyInt(42, SecurityPolicy.Performance);
        var barrier = new Barrier(threadCount);
        var results = new ConcurrentBag<int>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                var value = cyInt.ToInsecureInt();
                results.Add(value);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("concurrent decrypt of the same CyInt must be safe");
        results.Should().HaveCount(threadCount);
        results.Should().AllBeEquivalentTo(42, "every thread must see the same decrypted value");
    }

    [Fact]
    public async Task ConcurrentCreate_AllTypes_Parallel()
    {
        // Arrange: create thousands of different CyType instances in parallel
        var threadCount = StressTestConfig.ConcurrentThreads;
        var iterationsPerThread = 100;
        var barrier = new Barrier(threadCount);
        var exceptions = new ConcurrentBag<Exception>();
        var totalCreated = 0;

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(t => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < iterationsPerThread; i++)
            {
                try
                {
                    using var cyInt = new CyInt(i, SecurityPolicy.Performance);
                    using var cyStr = new CyString($"thread{t}_iter{i}", SecurityPolicy.Performance);
                    using var cyBool = new CyBool(i % 2 == 0, SecurityPolicy.Performance);
                    using var cyDouble = new CyDouble(i * 1.5, SecurityPolicy.Performance);
                    using var cyFloat = new CyFloat(i * 0.5f, SecurityPolicy.Performance);
                    using var cyLong = new CyLong((long)i * 1000, SecurityPolicy.Performance);

                    cyInt.ToInsecureInt().Should().Be(i);
                    cyStr.ToInsecureString().Should().Be($"thread{t}_iter{i}");

                    Interlocked.Increment(ref totalCreated);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("mass-creating CyTypes in parallel must not corrupt state");
        totalCreated.Should().Be(threadCount * iterationsPerThread);
    }

    [Fact]
    public async Task ConcurrentDispose_CyInt()
    {
        // Arrange: N threads all race to dispose the same CyInt
        var threadCount = StressTestConfig.ConcurrentThreads;
        var cyInt = new CyInt(99, SecurityPolicy.Performance);
        var barrier = new Barrier(threadCount);
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                cyInt.Dispose();
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("concurrent Dispose on CyInt must be idempotent");
        cyInt.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task ConcurrentOperatorOverloads()
    {
        // Arrange: N threads perform CyInt + CyInt using shared operands
        var threadCount = StressTestConfig.ConcurrentThreads;
        using var left = new CyInt(10, SecurityPolicy.Performance);
        using var right = new CyInt(20, SecurityPolicy.Performance);
        var barrier = new Barrier(threadCount);
        var results = new ConcurrentBag<int>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                using var sum = left + right;
                var value = sum.ToInsecureInt();
                results.Add(value);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("operator + must be safe under concurrent access");
        results.Should().HaveCount(threadCount);
        results.Should().AllBeEquivalentTo(30, "10 + 20 = 30 for every thread");
    }
}
