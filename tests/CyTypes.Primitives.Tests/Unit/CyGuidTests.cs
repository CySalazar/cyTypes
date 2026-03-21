using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyGuidTests
{
    [Fact]
    public void Roundtrip_preserves_value()
    {
        var guid = Guid.NewGuid();
        using var cy = new CyGuid(guid);
        cy.ToInsecureGuid().Should().Be(guid);
    }

    [Fact]
    public void Roundtrip_empty_guid()
    {
        using var cy = new CyGuid(Guid.Empty);
        cy.ToInsecureGuid().Should().Be(Guid.Empty);
    }

    [Fact]
    public void ToInsecureGuid_marks_compromised()
    {
        using var cy = new CyGuid(Guid.NewGuid());
        cy.IsCompromised.Should().BeFalse();
        _ = cy.ToInsecureGuid();
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Implicit_conversion()
    {
        var guid = Guid.NewGuid();
        CyGuid cy = guid;
        using (cy) { cy.ToInsecureGuid().Should().Be(guid); }
    }

    [Fact]
    public void Explicit_conversion_marks_compromised()
    {
        var guid = Guid.NewGuid();
        using var cy = new CyGuid(guid);
        Guid raw = (Guid)cy;
        raw.Should().Be(guid);
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void ToString_never_leaks_plaintext()
    {
        var guid = Guid.NewGuid();
        using var cy = new CyGuid(guid);
        cy.ToString().Should().Contain("Encrypted").And.NotContain(guid.ToString());
    }

    [Fact]
    public void Equality_same_guid()
    {
        var guid = Guid.NewGuid();
        using var a = new CyGuid(guid);
        using var b = new CyGuid(guid);
        (a == b).Should().BeTrue();
        (a != b).Should().BeFalse();
        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equality_different_guids()
    {
        using var a = new CyGuid(Guid.NewGuid());
        using var b = new CyGuid(Guid.NewGuid());
        (a == b).Should().BeFalse();
        (a != b).Should().BeTrue();
    }

    [Fact]
    public void Equality_with_null()
    {
        using var a = new CyGuid(Guid.NewGuid());
        a.Equals(null).Should().BeFalse();
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyGuid?)null == (CyGuid?)null).Should().BeTrue();
    }

    [Fact]
    public void Comparison_operators()
    {
        // Use deterministic GUIDs for consistent ordering
        var g1 = new Guid("00000000-0000-0000-0000-000000000001");
        var g2 = new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff");
        using var a = new CyGuid(g1);
        using var b = new CyGuid(g2);
        (a < b).Should().BeTrue();
        (b > a).Should().BeTrue();
        (a <= b).Should().BeTrue();
        (b >= a).Should().BeTrue();
    }

    [Fact]
    public void CompareTo_null_returns_positive()
    {
        using var a = new CyGuid(Guid.NewGuid());
        a.CompareTo(null).Should().BePositive();
    }

    [Fact]
    public void Equals_object_overload()
    {
        var guid = Guid.NewGuid();
        using var a = new CyGuid(guid);
        using var b = new CyGuid(guid);
        a.Equals((object)b).Should().BeTrue();
        a.Equals((object?)null).Should().BeFalse();
        a!.Equals((object)"not a guid").Should().BeFalse();
    }

    [Fact]
    public void GetHashCode_returns_instanceId_hash()
    {
        using var a = new CyGuid(Guid.NewGuid());
        a.GetHashCode().Should().Be(a.InstanceId.GetHashCode());
    }

    [Fact]
    public void Dispose_makes_ToInsecure_throw()
    {
        var cy = new CyGuid(Guid.NewGuid());
        cy.Dispose();
        var act = () => cy.ToInsecureGuid();
        act.Should().Throw<ObjectDisposedException>();
    }
}
