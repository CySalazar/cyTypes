using CyTypes.Core.Policy;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyTypeExtensionsTests
{
    [Fact]
    public void HasSamePolicy_same_policy_returns_true()
    {
        using var a = new CyInt(1);
        using var b = new CyInt(2);
        a.HasSamePolicy(b).Should().BeTrue();
    }

    [Fact]
    public void HasSamePolicy_different_policy_returns_false()
    {
        using var a = new CyInt(1, SecurityPolicy.Default);
        using var b = new CyInt(2, SecurityPolicy.Maximum);
        a.HasSamePolicy(b).Should().BeFalse();
    }

    [Fact]
    public void HasSamePolicy_null_a_throws()
    {
        using var b = new CyInt(1);
        ICyType a = null!;
        var act = () => a.HasSamePolicy(b);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void HasSamePolicy_null_b_throws()
    {
        using var a = new CyInt(1);
        var act = () => a.HasSamePolicy(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ResolvePolicy_returns_policy()
    {
        using var a = new CyInt(1);
        using var b = new CyInt(2);
        var resolved = a.ResolvePolicy(b);
        resolved.Should().NotBeNull();
    }

    [Fact]
    public void ResolvePolicy_null_a_throws()
    {
        using var b = new CyInt(1);
        ICyType a = null!;
        var act = () => a.ResolvePolicy(b);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ResolvePolicy_null_b_throws()
    {
        using var a = new CyInt(1);
        var act = () => a.ResolvePolicy(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
