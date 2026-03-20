using CyTypes.Core.Security;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Security;

public sealed class RateLimitTests
{
    [Fact]
    public void SecurityContext_with_no_rate_limit_allows_unlimited_decryptions()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 10_000);

        var act = () =>
        {
            for (int i = 0; i < 1_000; i++)
                ctx.IncrementDecryption();
        };

        act.Should().NotThrow();
        ctx.DecryptionCount.Should().Be(1_000);
    }

    [Fact]
    public void SecurityContext_with_rate_limit_throws_when_limit_exceeded_in_one_second_window()
    {
        const int rateLimit = 5;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 10_000, decryptionRateLimit: rateLimit);

        // Use up the entire rate limit
        for (int i = 0; i < rateLimit; i++)
            ctx.IncrementDecryption();

        // The next call should exceed the rate limit within the 1-second window
        var act = () => ctx.IncrementDecryption();

        act.Should().Throw<RateLimitExceededException>()
            .Which.Limit.Should().Be(rateLimit);
    }

    [Fact]
    public void Rate_limit_resets_after_time_window_passes()
    {
        const int rateLimit = 3;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 10_000, decryptionRateLimit: rateLimit);

        // Fill the rate limit window
        for (int i = 0; i < rateLimit; i++)
            ctx.IncrementDecryption();

        // Wait for the 1-second window to elapse
        Thread.Sleep(1100);

        // Should succeed after the window resets
        var act = () => ctx.IncrementDecryption();

        act.Should().NotThrow();
    }

    [Fact]
    public void Rate_limit_allows_exactly_limit_count_decryptions()
    {
        const int rateLimit = 10;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 10_000, decryptionRateLimit: rateLimit);

        var act = () =>
        {
            for (int i = 0; i < rateLimit; i++)
                ctx.IncrementDecryption();
        };

        act.Should().NotThrow();
        ctx.DecryptionCount.Should().Be(rateLimit);
    }

    [Fact]
    public async Task Rate_limit_concurrent_access_is_thread_safe()
    {
        const int rateLimit = 50;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 100_000, decryptionRateLimit: rateLimit);
        var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        // Fire many threads simultaneously
        var tasks = Enumerable.Range(0, 20).Select(_ => Task.Run(() =>
        {
            try
            {
                ctx.IncrementDecryption();
            }
            catch (RateLimitExceededException ex)
            {
                exceptions.Add(ex);
            }
        })).ToArray();

        await Task.WhenAll(tasks);

        // Some may succeed, some may throw — but no unhandled crash
        (ctx.DecryptionCount + exceptions.Count).Should().Be(20);
    }

    [Fact]
    public void SecurityContext_without_rate_limit_ignores_rate_check()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 100_000);

        var act = () =>
        {
            for (int i = 0; i < 500; i++)
                ctx.IncrementDecryption();
        };

        act.Should().NotThrow();
        ctx.DecryptionCount.Should().Be(500);
    }

    [Fact]
    public void Rate_limit_exception_contains_instance_id()
    {
        const int rateLimit = 2;
        var instanceId = Guid.NewGuid();
        var ctx = new SecurityContext(instanceId, maxDecryptionCount: 10_000, decryptionRateLimit: rateLimit);

        for (int i = 0; i < rateLimit; i++)
            ctx.IncrementDecryption();

        var act = () => ctx.IncrementDecryption();

        act.Should().Throw<RateLimitExceededException>()
            .Which.InstanceId.Should().Be(instanceId);
    }
}
