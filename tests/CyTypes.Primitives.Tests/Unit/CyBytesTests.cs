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
}
