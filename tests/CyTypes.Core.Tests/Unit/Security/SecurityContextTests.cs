using Xunit;
using FluentAssertions;
using CyTypes.Core.Security;

namespace CyTypes.Core.Tests.Unit.Security;

public class SecurityContextTests
{
    [Fact]
    public void NewContext_HasExpectedDefaults()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 5);

        ctx.IsCompromised.Should().BeFalse();
        ctx.IsTainted.Should().BeFalse();
        ctx.DecryptionCount.Should().Be(0);
        ctx.OperationCount.Should().Be(0);
    }

    [Fact]
    public void MarkCompromised_SetsIsCompromisedTrue()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 5);

        ctx.MarkCompromised();

        ctx.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void MarkTainted_SetsIsTaintedTrue()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 5);

        ctx.MarkTainted();

        ctx.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void ClearTaint_WithReason_ClearsTaint()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 5);
        ctx.MarkTainted();

        ctx.ClearTaint("resolved after investigation");

        ctx.IsTainted.Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ClearTaint_WithNullOrEmptyReason_ThrowsArgumentException(string? reason)
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 5);

        var act = () => ctx.ClearTaint(reason!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void IncrementDecryption_IncreasesDecryptionCount()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 100);

        ctx.IncrementDecryption();
        ctx.IncrementDecryption();
        ctx.IncrementDecryption();

        ctx.DecryptionCount.Should().Be(3);
    }

    [Fact]
    public void IncrementOperation_IncreasesOperationCount()
    {
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 5);

        ctx.IncrementOperation();
        ctx.IncrementOperation();

        ctx.OperationCount.Should().Be(2);
    }

    [Fact]
    public void AutoDestroyTriggered_FiresWhenDecryptionCountReachesMax()
    {
        const int max = 3;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: max);
        SecurityContext? captured = null;
        ctx.AutoDestroyTriggered += c => captured = c;

        for (int i = 0; i < max; i++)
            ctx.IncrementDecryption();

        captured.Should().NotBeNull();
        captured.Should().BeSameAs(ctx);
    }

    [Fact]
    public void AutoDestroyTriggered_DoesNotFireBeforeReachingLimit()
    {
        const int max = 5;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: max);
        bool fired = false;
        ctx.AutoDestroyTriggered += _ => fired = true;

        for (int i = 0; i < max - 1; i++)
            ctx.IncrementDecryption();

        fired.Should().BeFalse();
    }

    [Fact]
    public void IsAutoDestroyed_SetToTrueAfterAutoDestroy()
    {
        const int max = 2;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: max);

        for (int i = 0; i < max; i++)
            ctx.IncrementDecryption();

        ctx.IsAutoDestroyed.Should().BeTrue();
    }

    [Fact]
    public void CreatedUtc_IsApproximatelyNow()
    {
        var before = DateTime.UtcNow;
        var ctx = new SecurityContext(Guid.NewGuid(), maxDecryptionCount: 5);
        var after = DateTime.UtcNow;

        ctx.CreatedUtc.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
    }

    [Fact]
    public void InstanceId_MatchesConstructorArgument()
    {
        var id = Guid.NewGuid();

        var ctx = new SecurityContext(id, maxDecryptionCount: 5);

        ctx.InstanceId.Should().Be(id);
    }
}
