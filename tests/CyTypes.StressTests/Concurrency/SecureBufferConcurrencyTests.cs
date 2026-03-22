using System.Collections.Concurrent;
using CyTypes.Core.Memory;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class SecureBufferConcurrencyTests
{
    [Fact]
    public async Task MassiveConcurrentDispose_AllSucceed()
    {
        // Arrange: one buffer, N threads all racing to dispose it
        var buffer = new SecureBuffer(256);
        var threadCount = StressTestConfig.ConcurrentThreads;
        var barrier = new Barrier(threadCount);
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                buffer.Dispose();
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert: no exceptions, buffer is disposed
        exceptions.Should().BeEmpty("concurrent Dispose must be idempotent and never throw");
        buffer.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task ConcurrentAllocateAndDispose_Rapid()
    {
        // Arrange: each thread allocates and disposes its own buffer in a tight loop
        var threadCount = StressTestConfig.ConcurrentThreads;
        var iterations = StressTestConfig.IterationsPerThread;
        var barrier = new Barrier(threadCount);
        var exceptions = new ConcurrentBag<Exception>();
        var totalAllocated = 0;

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            for (var i = 0; i < iterations; i++)
            {
                try
                {
                    var buf = new SecureBuffer(64);
                    buf.Write(new byte[] { 0xAA, 0xBB, 0xCC });
                    buf.Dispose();
                    Interlocked.Increment(ref totalAllocated);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("rapid alloc/dispose must not throw");
        totalAllocated.Should().Be(threadCount * iterations);
    }

    [Theory]
    [InlineData(10_000)]
    public async Task DisposeRace_WithAsSpan_HighIteration(int totalIterations)
    {
        // Characterization: one thread disposes while another reads AsSpan
        // Expect either success or ObjectDisposedException, nothing else.
        var exceptions = new ConcurrentBag<Exception>();

        for (var i = 0; i < totalIterations; i++)
        {
            var buffer = new SecureBuffer(32);
            buffer.Write(new byte[32]);

            var barrier = new Barrier(2);

            var disposeTask = Task.Run(() =>
            {
                barrier.SignalAndWait();
                buffer.Dispose();
            });

            var readTask = Task.Run(() =>
            {
                barrier.SignalAndWait();
                try
                {
                    _ = buffer.AsSpan();
                }
                catch (ObjectDisposedException)
                {
                    // Expected race outcome
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            await Task.WhenAll(disposeTask, readTask);
        }

        // Assert: the only acceptable exception is ObjectDisposedException (already caught above)
        exceptions.Should().BeEmpty(
            "the only valid outcomes are a successful read or ObjectDisposedException");
    }
}
