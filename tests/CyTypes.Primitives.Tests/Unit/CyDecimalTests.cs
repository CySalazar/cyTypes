using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyDecimalTests
{
    [Theory]
    [InlineData("0")]
    [InlineData("-1.5")]
    [InlineData("79228162514264337593543950335")]  // decimal.MaxValue
    [InlineData("-79228162514264337593543950335")] // decimal.MinValue
    [InlineData("3.14159265358979")]
    public void Roundtrip_preserves_value(string valueStr)
    {
        var value = decimal.Parse(valueStr, System.Globalization.CultureInfo.InvariantCulture);
        using var cy = new CyDecimal(value);
        cy.ToInsecureDecimal().Should().Be(value);
    }

    [Fact]
    public void Implicit_conversion() { CyDecimal cy = 99.99m; using (cy) { cy.ToInsecureDecimal().Should().Be(99.99m); } }

    [Fact]
    public void Explicit_conversion_marks_compromised()
    {
        using var cy = new CyDecimal(42.5m);
        decimal raw = (decimal)cy;
        raw.Should().Be(42.5m);
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Add_operator() { using var a = new CyDecimal(1.1m); using var b = new CyDecimal(2.2m); using var c = a + b; c.ToInsecureDecimal().Should().Be(3.3m); }
    [Fact]
    public void Subtract_operator() { using var a = new CyDecimal(5.5m); using var b = new CyDecimal(2.2m); using var c = a - b; c.ToInsecureDecimal().Should().Be(3.3m); }
    [Fact]
    public void Multiply_operator() { using var a = new CyDecimal(3m); using var b = new CyDecimal(4m); using var c = a * b; c.ToInsecureDecimal().Should().Be(12m); }
    [Fact]
    public void Divide_operator() { using var a = new CyDecimal(10m); using var b = new CyDecimal(4m); using var c = a / b; c.ToInsecureDecimal().Should().Be(2.5m); }
    [Fact]
    public void Modulo_operator() { using var a = new CyDecimal(17m); using var b = new CyDecimal(5m); using var c = a % b; c.ToInsecureDecimal().Should().Be(2m); }

    [Fact]
    public void Equality_operators()
    {
        using var a = new CyDecimal(3.14m);
        using var b = new CyDecimal(3.14m);
        using var c = new CyDecimal(2.71m);
        (a == b).Should().BeTrue();
        (a != c).Should().BeTrue();
    }

    [Fact]
    public void Comparison_operators()
    {
        using var a = new CyDecimal(1m);
        using var b = new CyDecimal(2m);
        (a < b).Should().BeTrue();
        (b > a).Should().BeTrue();
        (a <= b).Should().BeTrue();
        (b >= a).Should().BeTrue();
    }

    [Fact]
    public void Taint_propagates()
    {
        using var a = new CyDecimal(1m); a.MarkTainted();
        using var b = new CyDecimal(2m);
        using var c = a + b;
        c.IsTainted.Should().BeTrue();
    }
}
