using System.Collections.Concurrent;
using CyTypes.Core.Memory;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class SecureBufferPoolConcurrencyTests
{
    [Fact]
    public async Task HighContention_RentReturn_NoLoss()
    {
        // Arrange: N threads each rent and return buffers in a tight loop
        var threadCount = StressTestConfig.ConcurrentThreads;
        var iterations = StressTestConfig.IterationsPerThread;
        var pool = new SecureBufferPool(128);
        var barrier = new Barrier(threadCount);
        var exceptions = new ConcurrentBag<Exception>();
        var totalRentReturn = 0;

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < iterations; i++)
            {
                try
                {
                    var buf = pool.Rent();
                    buf.Length.Should().Be(128);
                    buf.Write(new byte[] { 0xFF });
                    pool.Return(buf);
                    Interlocked.Increment(ref totalRentReturn);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("concurrent rent/return must not corrupt the pool");
        totalRentReturn.Should().Be(threadCount * iterations);

        // Cleanup
        pool.Dispose();
    }

    [Fact]
    public async Task RentDuringDispose_ThrowsObjectDisposed()
    {
        // Arrange: one thread disposes the pool while others try to rent
        var threadCount = StressTestConfig.ConcurrentThreads;
        var pool = new SecureBufferPool(64);
        var barrier = new Barrier(threadCount + 1); // +1 for the dispose thread
        var objectDisposedCount = 0;
        var successCount = 0;
        var unexpectedExceptions = new ConcurrentBag<Exception>();

        // Pre-fill the pool
        for (var i = 0; i < 50; i++)
        {
            var buf = new SecureBuffer(64);
            pool.Return(buf);
        }

        // Act
        var disposeTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            pool.Dispose();
        });

        var rentTasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                var buf = pool.Rent();
                pool.Return(buf);
                Interlocked.Increment(ref successCount);
            }
            catch (ObjectDisposedException)
            {
                Interlocked.Increment(ref objectDisposedCount);
            }
            catch (Exception ex)
            {
                unexpectedExceptions.Add(ex);
            }
        }));

        await Task.WhenAll(rentTasks.Append(disposeTask));

        // Assert: every thread either succeeded or got ObjectDisposedException
        unexpectedExceptions.Should().BeEmpty(
            "only ObjectDisposedException is acceptable when pool is disposing");
        (successCount + objectDisposedCount).Should().Be(threadCount);
    }
}
