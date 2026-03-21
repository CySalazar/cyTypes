using CyTypes.Core.Policy.Components;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Policy;

public sealed class KeyRotationPolicyTests
{
    [Fact]
    public void EveryNOperations_stores_value()
    {
        var policy = KeyRotationPolicy.EveryNOperations(10);
        policy.Kind.Should().Be(KeyRotationKind.EveryNOperations);
        policy.Value.Should().Be(10);
    }

    [Fact]
    public void EveryNOperations_zero_throws()
    {
        var act = () => KeyRotationPolicy.EveryNOperations(0);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void EveryNOperations_negative_throws()
    {
        var act = () => KeyRotationPolicy.EveryNOperations(-1);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void EveryNMinutes_stores_value()
    {
        var policy = KeyRotationPolicy.EveryNMinutes(30);
        policy.Kind.Should().Be(KeyRotationKind.EveryNMinutes);
        policy.Value.Should().Be(30);
    }

    [Fact]
    public void EveryNMinutes_zero_throws()
    {
        var act = () => KeyRotationPolicy.EveryNMinutes(0);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Manual_has_zero_value()
    {
        var policy = KeyRotationPolicy.Manual;
        policy.Kind.Should().Be(KeyRotationKind.Manual);
        policy.Value.Should().Be(0);
    }

    [Fact]
    public void EveryTimeSpan_converts_to_minutes()
    {
        var policy = KeyRotationPolicy.EveryTimeSpan(TimeSpan.FromHours(2));
        policy.Kind.Should().Be(KeyRotationKind.EveryNMinutes);
        policy.Value.Should().Be(120);
    }

    [Fact]
    public void EveryTimeSpan_zero_throws()
    {
        var act = () => KeyRotationPolicy.EveryTimeSpan(TimeSpan.Zero);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void ToString_EveryNOperations()
    {
        KeyRotationPolicy.EveryNOperations(5).ToString().Should().Be("Every 5 operations");
    }

    [Fact]
    public void ToString_EveryNMinutes()
    {
        KeyRotationPolicy.EveryNMinutes(10).ToString().Should().Be("Every 10 minutes");
    }

    [Fact]
    public void ToString_Manual()
    {
        KeyRotationPolicy.Manual.ToString().Should().Be("Manual");
    }
}
