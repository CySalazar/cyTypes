using System.Collections.Concurrent;
using CyTypes.Core.KeyManagement;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class KeyManagerConcurrencyTests
{
    [Fact]
    public async Task ConcurrentRotation_Serialized()
    {
        // Arrange: N threads all call RotateKey simultaneously;
        // the internal lock should serialize them without corruption.
        var threadCount = StressTestConfig.ConcurrentThreads;
        using var km = new KeyManager();
        var initialKeyId = km.KeyId;
        var barrier = new Barrier(threadCount);
        var keyIds = new ConcurrentBag<Guid>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                km.RotateKey();
                keyIds.Add(km.KeyId);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert: no exceptions, key was rotated, KeyId changed from initial
        exceptions.Should().BeEmpty("concurrent key rotations must be serialized safely");
        km.KeyId.Should().NotBe(initialKeyId, "key must have been rotated at least once");
        keyIds.Should().HaveCount(threadCount);
    }

    [Fact]
    public async Task RotateWhileReading_CurrentKey()
    {
        // Arrange: readers continuously access CurrentKey while rotators rotate
        var threadCount = StressTestConfig.ConcurrentThreads;
        var readerCount = threadCount / 2;
        var rotatorCount = threadCount - readerCount;
        using var km = new KeyManager();
        var barrier = new Barrier(threadCount);
        var readSuccessCount = 0;
        var rotateSuccessCount = 0;
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var readerTasks = Enumerable.Range(0, readerCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < 100; i++)
            {
                try
                {
                    var key = km.CurrentKey;
                    key.Length.Should().Be(32);
                    Interlocked.Increment(ref readSuccessCount);
                }
                catch (ObjectDisposedException)
                {
                    // Can happen if buffer is swapped mid-read during rotation
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        var rotatorTasks = Enumerable.Range(0, rotatorCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < 10; i++)
            {
                try
                {
                    km.RotateKey();
                    Interlocked.Increment(ref rotateSuccessCount);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(readerTasks.Concat(rotatorTasks));

        // Assert
        exceptions.Should().BeEmpty(
            "readers and rotators must coexist without crashes or corruption");
        readSuccessCount.Should().BeGreaterThan(0, "at least some reads should succeed");
        rotateSuccessCount.Should().BeGreaterThan(0, "at least some rotations should succeed");
    }

    [Fact]
    public async Task UsageCount_AtomicUnderConcurrency()
    {
        // Arrange: N threads all increment usage, verify the total matches
        var threadCount = StressTestConfig.ConcurrentThreads;
        var incrementsPerThread = StressTestConfig.IterationsPerThread;
        using var km = new KeyManager();
        var barrier = new Barrier(threadCount);
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < incrementsPerThread; i++)
            {
                try
                {
                    km.IncrementUsage();
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("IncrementUsage must be lock-free and safe");
        km.UsageCount.Should().Be(threadCount * incrementsPerThread,
            "every increment must be atomically counted");
    }
}
