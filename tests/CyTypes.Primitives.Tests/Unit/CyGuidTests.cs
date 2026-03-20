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
}
