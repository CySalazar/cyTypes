using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyBytesTests
{
    [Fact]
    public void Roundtrip_preserves_value()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        using var cy = new CyBytes(data);
        cy.ToInsecureBytes().Should().BeEquivalentTo(data);
    }

    [Fact]
    public void Length_property_matches_without_decrypt()
    {
        var data = new byte[] { 10, 20, 30 };
        using var cy = new CyBytes(data);
        cy.Length.Should().Be(3);
        cy.IsCompromised.Should().BeFalse();
    }

    [Fact]
    public void ToInsecureBytes_marks_compromised()
    {
        using var cy = new CyBytes(new byte[] { 1 });
        _ = cy.ToInsecureBytes();
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Empty_array_roundtrip()
    {
        using var cy = new CyBytes([]);
        cy.ToInsecureBytes().Should().BeEmpty();
        cy.Length.Should().Be(0);
    }

    [Fact]
    public void Implicit_conversion()
    {
        CyBytes cy = new byte[] { 42 };
        using (cy)
        {
            cy.ToInsecureBytes().Should().BeEquivalentTo(new byte[] { 42 });
        }
    }

    [Fact]
    public void Explicit_conversion_marks_compromised()
    {
        using var cy = new CyBytes(new byte[] { 1, 2, 3 });
        byte[] raw = (byte[])cy;
        raw.Should().BeEquivalentTo(new byte[] { 1, 2, 3 });
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void ToString_never_leaks_content()
    {
        using var cy = new CyBytes(new byte[] { 0xDE, 0xAD });
        cy.ToString().Should().Contain("Encrypted");
    }

    [Fact]
    public void Constructor_clones_input()
    {
        var original = new byte[] { 1, 2, 3, 4, 5 };
        using var cy = new CyBytes(original);

        // Mutate the original array after construction
        original[0] = 0xFF;
        original[1] = 0xFF;

        // Verify CyBytes still has the original data
        var retrieved = cy.ToInsecureBytes();
        retrieved[0].Should().Be(1);
        retrieved[1].Should().Be(2);
    }

    [Fact]
    public void Equality_same_content()
    {
        using var a = new CyBytes(new byte[] { 1, 2, 3 });
        using var b = new CyBytes(new byte[] { 1, 2, 3 });
        (a == b).Should().BeTrue();
        (a != b).Should().BeFalse();
        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equality_different_content()
    {
        using var a = new CyBytes(new byte[] { 1, 2, 3 });
        using var b = new CyBytes(new byte[] { 4, 5, 6 });
        (a == b).Should().BeFalse();
        (a != b).Should().BeTrue();
    }

    [Fact]
    public void Equality_with_null()
    {
        using var a = new CyBytes(new byte[] { 1 });
        a.Equals(null).Should().BeFalse();
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyBytes?)null == (CyBytes?)null).Should().BeTrue();
    }

    [Fact]
    public void Comparison_operators()
    {
        using var a = new CyBytes(new byte[] { 1, 2 });
        using var b = new CyBytes(new byte[] { 1, 3 });
        (a < b).Should().BeTrue();
        (b > a).Should().BeTrue();
        (a <= b).Should().BeTrue();
        (b >= a).Should().BeTrue();
    }

    [Fact]
    public void CompareTo_null_returns_positive()
    {
        using var a = new CyBytes(new byte[] { 1 });
        a.CompareTo(null).Should().BePositive();
    }

    [Fact]
    public void Equals_object_overload()
    {
        using var a = new CyBytes(new byte[] { 1, 2 });
        using var b = new CyBytes(new byte[] { 1, 2 });
        a.Equals((object)b).Should().BeTrue();
        a.Equals((object?)null).Should().BeFalse();
        a!.Equals((object)"not a CyBytes").Should().BeFalse();
    }

    [Fact]
    public void GetHashCode_returns_value()
    {
        using var a = new CyBytes(new byte[] { 1 });
        a.GetHashCode().Should().Be(a.InstanceId.GetHashCode());
    }

    [Fact]
    public void Dispose_makes_ToInsecure_throw()
    {
        var cy = new CyBytes(new byte[] { 1 });
        cy.Dispose();
        var act = () => cy.ToInsecureBytes();
        act.Should().Throw<ObjectDisposedException>();
    }
}
