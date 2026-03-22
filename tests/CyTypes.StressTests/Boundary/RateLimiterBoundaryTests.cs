using CyTypes.Core.Security;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Boundary;

[Trait("Category", "Stress")]
[Trait("SubCategory", "Boundary")]
public class RateLimiterBoundaryTests
{
    private readonly ITestOutputHelper _output;

    public RateLimiterBoundaryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void RateLimit_ExactlyAtLimit_NoException()
    {
        // SecurityContext with rateLimit=100, maxDecryption=int.MaxValue
        // The circular buffer holds 100 entries. The first 100 calls fill it;
        // since the oldest entry is always within the 1-second window initially,
        // the 101st call would throw — but exactly 100 should succeed.
        var ctx = new SecurityContext(Guid.NewGuid(), int.MaxValue, decryptionRateLimit: 100);

        var action = () =>
        {
            for (var i = 0; i < 100; i++)
            {
                ctx.IncrementDecryption();
            }
        };

        action.Should().NotThrow("100 calls within a rate limit of 100/sec should not exceed the limit");
        ctx.DecryptionCount.Should().Be(100);
        _output.WriteLine($"100 IncrementDecryption calls completed without exception (count={ctx.DecryptionCount})");
    }

    [Fact]
    public void RateLimit_BurstThenWait_ThenBurst()
    {
        const int rateLimit = 50;
        var ctx = new SecurityContext(Guid.NewGuid(), int.MaxValue, decryptionRateLimit: rateLimit);

        // First burst — fill the rate limit window
        for (var i = 0; i < rateLimit; i++)
        {
            ctx.IncrementDecryption();
        }

        _output.WriteLine($"First burst of {rateLimit} completed (count={ctx.DecryptionCount})");

        // Wait for the 1-second window to expire
        Thread.Sleep(1100);

        // Second burst — should succeed because the window has elapsed
        var action = () =>
        {
            for (var i = 0; i < rateLimit; i++)
            {
                ctx.IncrementDecryption();
            }
        };

        action.Should().NotThrow("after waiting 1.1s, the rate limit window should have expired");
        ctx.DecryptionCount.Should().Be(rateLimit * 2);
        _output.WriteLine($"Second burst of {rateLimit} completed (total count={ctx.DecryptionCount})");
    }

    [Fact]
    public void RateLimit_UnderLoad_ThrowsWhenExceeded()
    {
        const int rateLimit = 5;
        var ctx = new SecurityContext(Guid.NewGuid(), int.MaxValue, decryptionRateLimit: rateLimit);
        var threw = false;

        // Call IncrementDecryption rapidly until RateLimitExceededException is thrown
        try
        {
            // We need more than rateLimit calls within 1 second to trigger the exception
            for (var i = 0; i < rateLimit * 10; i++)
            {
                ctx.IncrementDecryption();
            }
        }
        catch (RateLimitExceededException ex)
        {
            threw = true;
            _output.WriteLine($"RateLimitExceededException thrown at count={ctx.DecryptionCount}: {ex.Message}");
            ex.Limit.Should().Be(rateLimit);
        }

        threw.Should().BeTrue(
            "rapidly exceeding the rate limit of {0}/sec should throw RateLimitExceededException", rateLimit);
    }
}
