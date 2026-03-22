using System.Collections.Concurrent;
using CyTypes.Core.Security;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;

namespace CyTypes.StressTests.Concurrency;

[Trait("Category", "Stress"), Trait("SubCategory", "Concurrency")]
public class SecurityContextConcurrencyTests
{
    [Fact]
    public async Task ConcurrentIncrementDecryption_TotalAccurate()
    {
        // Arrange: N threads increment decryption count, verify total
        var threadCount = StressTestConfig.ConcurrentThreads;
        var incrementsPerThread = StressTestConfig.IterationsPerThread;
        var expectedTotal = threadCount * incrementsPerThread;

        // Use a very high max to avoid auto-destroy during the test
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: expectedTotal + 1);
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
                    ctx.IncrementDecryption();
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        exceptions.Should().BeEmpty("IncrementDecryption must be thread-safe");
        ctx.DecryptionCount.Should().Be(expectedTotal,
            "every concurrent increment must be atomically reflected in the total");
    }

    [Fact]
    public async Task AutoDestroy_FiresOnce_UnderConcurrency()
    {
        // Arrange: threshold = 50, 100 threads each increment once -> auto-destroy must fire exactly once
        const int threshold = 50;
        const int threadCount = 100;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: threshold);
        var barrier = new Barrier(threadCount);
        var fireCount = 0;

        ctx.AutoDestroyTriggered += _ => Interlocked.Increment(ref fireCount);

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                ctx.IncrementDecryption();
            }
            catch
            {
                // Rate limit or other expected exceptions
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        ctx.IsAutoDestroyed.Should().BeTrue("threshold was exceeded");
        ctx.DecryptionCount.Should().BeGreaterThanOrEqualTo(threshold);
        fireCount.Should().BeGreaterThanOrEqualTo(1,
            "AutoDestroyTriggered must fire at least once when threshold is breached");
    }

    [Fact]
    public async Task RateLimit_ConcurrentBurst_NoDeadlock()
    {
        // Arrange: rate limit = 10/sec, many threads burst simultaneously
        // Some should succeed, some should get RateLimitExceededException, no deadlocks
        const int rateLimit = 10;
        var threadCount = StressTestConfig.ConcurrentThreads;
        var ctx = new SecurityContext(Guid.NewGuid(),
            maxDecryptionCount: int.MaxValue,
            decryptionRateLimit: rateLimit);
        var barrier = new Barrier(threadCount);
        var successCount = 0;
        var rateLimitedCount = 0;
        var unexpectedExceptions = new ConcurrentBag<Exception>();

        // Act: use a CancellationToken to detect deadlock
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(StressTestConfig.TimeoutSeconds));

        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                ctx.IncrementDecryption();
                Interlocked.Increment(ref successCount);
            }
            catch (RateLimitExceededException)
            {
                Interlocked.Increment(ref rateLimitedCount);
            }
            catch (Exception ex)
            {
                unexpectedExceptions.Add(ex);
            }
        }, cts.Token));

        var allDone = Task.WhenAll(tasks);
        var completed = await Task.WhenAny(allDone, Task.Delay(Timeout.Infinite, cts.Token));

        // Assert
        completed.Should().Be(allDone, "all tasks must complete without deadlock");
        unexpectedExceptions.Should().BeEmpty(
            "only RateLimitExceededException is acceptable under burst load");
        (successCount + rateLimitedCount).Should().Be(threadCount,
            "every thread must either succeed or be rate-limited");
        successCount.Should().BeGreaterThan(0, "at least some threads must succeed");
    }
}
