using System.Globalization;
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
        (1.0 / value).Should().Be(double.NegativeInfinity);
    }

    [Fact]
    public void Parse_string() { using var cy = CyDouble.Parse("3.14", CultureInfo.InvariantCulture); cy.ToInsecureDouble().Should().Be(3.14); }

    [Fact]
    public void Parse_span() { using var cy = CyDouble.Parse("3.14".AsSpan(), CultureInfo.InvariantCulture); cy.ToInsecureDouble().Should().Be(3.14); }

    [Fact]
    public void TryParse_valid() { CyDouble.TryParse("2.71", out var r).Should().BeTrue(); using (r) { r!.ToInsecureDouble().Should().Be(2.71); } }

    [Fact]
    public void TryParse_invalid() { CyDouble.TryParse("abc", out var r).Should().BeFalse(); r.Should().BeNull(); }

    [Fact]
    public void TryParse_span_valid() { CyDouble.TryParse("1.5".AsSpan(), CultureInfo.InvariantCulture, out var r).Should().BeTrue(); using (r) { r!.ToInsecureDouble().Should().Be(1.5); } }

    [Fact]
    public void TryParse_span_invalid() { CyDouble.TryParse("xyz".AsSpan(), CultureInfo.InvariantCulture, out var r).Should().BeFalse(); r.Should().BeNull(); }

    [Fact]
    public void MinValue_static() { using var cy = CyDouble.MinValue; cy.ToInsecureDouble().Should().Be(double.MinValue); }

    [Fact]
    public void MaxValue_static() { using var cy = CyDouble.MaxValue; cy.ToInsecureDouble().Should().Be(double.MaxValue); }

    [Fact]
    public void PositiveInfinity_static() { using var cy = CyDouble.PositiveInfinity; double.IsPositiveInfinity(cy.ToInsecureDouble()).Should().BeTrue(); }

    [Fact]
    public void NegativeInfinity_static() { using var cy = CyDouble.NegativeInfinity; double.IsNegativeInfinity(cy.ToInsecureDouble()).Should().BeTrue(); }

    [Fact]
    public void NaN_static() { using var cy = CyDouble.NaN; double.IsNaN(cy.ToInsecureDouble()).Should().BeTrue(); }

    [Fact]
    public void Epsilon_static() { using var cy = CyDouble.Epsilon; cy.ToInsecureDouble().Should().Be(double.Epsilon); }

    [Fact]
    public void CompareTo_null_returns_positive() { using var cy = new CyDouble(1.0); cy.CompareTo(null).Should().BePositive(); }

    [Fact]
    public void CompareTo_equal() { using var a = new CyDouble(1.0); using var b = new CyDouble(1.0); a.CompareTo(b).Should().Be(0); }

    [Fact]
    public void Dispose_throws() { var cy = new CyDouble(1.0); cy.Dispose(); var act = () => cy.ToInsecureDouble(); act.Should().Throw<ObjectDisposedException>(); }

    [Fact]
    public void ToString_never_leaks() { using var cy = new CyDouble(3.14); cy.ToString().Should().Contain("Encrypted"); }

    [Fact]
    public void Null_equality()
    {
        using var a = new CyDouble(1.0);
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyDouble?)null == null).Should().BeTrue();
    }

    [Fact]
    public void LessThanOrEqual_and_GreaterThanOrEqual()
    {
        using var a = new CyDouble(1.0);
        using var b = new CyDouble(1.0);
        (a <= b).Should().BeTrue();
        (a >= b).Should().BeTrue();
    }

    [Fact]
    public void Modulo_operator() { using var a = new CyDouble(10.0); using var b = new CyDouble(3.0); using var c = a % b; c.ToInsecureDouble().Should().Be(1.0); }

    [Fact]
    public void UnaryPlus_ReturnsNewInstanceWithSameValue()
    {
        using var a = new CyDouble(3.14);
        using var b = +a;
        b.ToInsecureDouble().Should().Be(3.14);
        b.InstanceId.Should().NotBe(a.InstanceId);
    }

    [Fact]
    public void UnaryMinus_ReturnsNegatedValue()
    {
        using var a = new CyDouble(3.14);
        using var b = -a;
        b.ToInsecureDouble().Should().Be(-3.14);
    }

    [Fact]
    public void Increment_ReturnsValuePlusOne()
    {
        var a = new CyDouble(10.0);
        using var b = ++a;
        b.ToInsecureDouble().Should().Be(11.0);
    }

    [Fact]
    public void Decrement_ReturnsValueMinusOne()
    {
        var a = new CyDouble(10.0);
        using var b = --a;
        b.ToInsecureDouble().Should().Be(9.0);
    }

    [Fact]
    public void UnaryOperators_PropagateTaint()
    {
        using var a = new CyDouble(5.0);
        a.MarkTainted();
        using var pos = +a;
        using var neg = -a;
        pos.IsTainted.Should().BeTrue();
        neg.IsTainted.Should().BeTrue();
    }
}
