using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyDateTimeTests
{
    [Fact]
    public void Roundtrip_MinValue()
    {
        using var cy = new CyDateTime(DateTime.MinValue);
        cy.ToInsecureDateTime().Should().Be(DateTime.MinValue);
    }

    [Fact]
    public void Roundtrip_MaxValue()
    {
        using var cy = new CyDateTime(DateTime.MaxValue);
        cy.ToInsecureDateTime().Should().Be(DateTime.MaxValue);
    }

    [Fact]
    public void Roundtrip_UtcNow()
    {
        var now = DateTime.UtcNow;
        using var cy = new CyDateTime(now);
        cy.ToInsecureDateTime().Ticks.Should().Be(now.Ticks);
    }

    [Fact]
    public void Roundtrip_specific_date()
    {
        var date = new DateTime(2024, 6, 15, 14, 30, 0, DateTimeKind.Utc);
        using var cy = new CyDateTime(date);
        cy.ToInsecureDateTime().Ticks.Should().Be(date.Ticks);
    }

    [Fact]
    public void Implicit_conversion()
    {
        var date = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        CyDateTime cy = date;
        using (cy) { cy.ToInsecureDateTime().Ticks.Should().Be(date.Ticks); }
    }

    [Fact]
    public void Explicit_conversion_marks_compromised()
    {
        var date = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        using var cy = new CyDateTime(date);
        DateTime raw = (DateTime)cy;
        raw.Ticks.Should().Be(date.Ticks);
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Equality_operators()
    {
        var d1 = new DateTime(2024, 6, 15, 0, 0, 0, DateTimeKind.Utc);
        var d2 = new DateTime(2024, 6, 15, 0, 0, 0, DateTimeKind.Utc);
        var d3 = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        using var a = new CyDateTime(d1);
        using var b = new CyDateTime(d2);
        using var c = new CyDateTime(d3);
        (a == b).Should().BeTrue();
        (a != c).Should().BeTrue();
    }

    [Fact]
    public void Null_equality()
    {
        using var a = new CyDateTime(DateTime.UtcNow);
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyDateTime?)null == null).Should().BeTrue();
    }

    [Fact]
    public void Comparison_operators()
    {
        var earlier = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var later = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        using var a = new CyDateTime(earlier);
        using var b = new CyDateTime(later);
        (a < b).Should().BeTrue();
        (b > a).Should().BeTrue();
        (a <= b).Should().BeTrue();
        (b >= a).Should().BeTrue();
    }

    [Fact]
    public void ToString_never_leaks()
    {
        using var cy = new CyDateTime(DateTime.UtcNow);
        cy.ToString().Should().Contain("Encrypted");
    }
}
