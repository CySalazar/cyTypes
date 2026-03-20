using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyDoubleTests
{
    [Theory]
    [InlineData(0.0)]
    [InlineData(-1.5)]
    [InlineData(3.14159)]
    [InlineData(double.MaxValue)]
    [InlineData(double.MinValue)]
    [InlineData(double.Epsilon)]
    public void Roundtrip_preserves_value(double value)
    {
        using var cy = new CyDouble(value);
        cy.ToInsecureDouble().Should().Be(value);
    }

    [Fact]
    public void Roundtrip_NaN()
    {
        using var cy = new CyDouble(double.NaN);
        double.IsNaN(cy.ToInsecureDouble()).Should().BeTrue();
    }

    [Fact]
    public void Roundtrip_PositiveInfinity()
    {
        using var cy = new CyDouble(double.PositiveInfinity);
        double.IsPositiveInfinity(cy.ToInsecureDouble()).Should().BeTrue();
    }

    [Fact]
    public void Roundtrip_NegativeInfinity()
    {
        using var cy = new CyDouble(double.NegativeInfinity);
        double.IsNegativeInfinity(cy.ToInsecureDouble()).Should().BeTrue();
    }

    [Fact]
    public void Implicit_conversion() { CyDouble cy = 3.14; using (cy) { cy.ToInsecureDouble().Should().Be(3.14); } }

    [Fact]
    public void Explicit_conversion_marks_compromised()
    {
        using var cy = new CyDouble(2.71);
        double raw = (double)cy;
        raw.Should().Be(2.71);
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Add_operator() { using var a = new CyDouble(1.5); using var b = new CyDouble(2.5); using var c = a + b; c.ToInsecureDouble().Should().Be(4.0); }
    [Fact]
    public void Subtract_operator() { using var a = new CyDouble(5.0); using var b = new CyDouble(2.0); using var c = a - b; c.ToInsecureDouble().Should().Be(3.0); }
    [Fact]
    public void Multiply_operator() { using var a = new CyDouble(3.0); using var b = new CyDouble(4.0); using var c = a * b; c.ToInsecureDouble().Should().Be(12.0); }
    [Fact]
    public void Divide_operator() { using var a = new CyDouble(10.0); using var b = new CyDouble(4.0); using var c = a / b; c.ToInsecureDouble().Should().Be(2.5); }

    [Fact]
    public void Equality_operators()
    {
        using var a = new CyDouble(3.14);
        using var b = new CyDouble(3.14);
        using var c = new CyDouble(2.71);
        (a == b).Should().BeTrue();
        (a != c).Should().BeTrue();
    }

    [Fact]
    public void Comparison_operators()
    {
        using var a = new CyDouble(1.0);
        using var b = new CyDouble(2.0);
        (a < b).Should().BeTrue();
        (b > a).Should().BeTrue();
    }

    [Fact]
    public void Taint_propagates()
    {
        using var a = new CyDouble(1.0); a.MarkTainted();
        using var b = new CyDouble(2.0);
        using var c = a + b;
        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void NaN_not_equal_to_NaN()
    {
        using var a = new CyDouble(double.NaN);
        using var b = new CyDouble(double.NaN);
        (a == b).Should().BeFalse();
    }

    [Fact]
    public void NegativeZero_roundtrip()
    {
        using var cy = new CyDouble(-0.0);
        var value = cy.ToInsecureDouble();
        // Verify it roundtrips as negative zero
        (1.0 / value).Should().Be(double.NegativeInfinity);
    }
}
