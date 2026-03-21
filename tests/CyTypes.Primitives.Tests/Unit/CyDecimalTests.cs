using System.Globalization;
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

    [Fact]
    public void Parse_string() { using var cy = CyDecimal.Parse("99.99", CultureInfo.InvariantCulture); cy.ToInsecureDecimal().Should().Be(99.99m); }

    [Fact]
    public void Parse_span() { using var cy = CyDecimal.Parse("99.99".AsSpan(), CultureInfo.InvariantCulture); cy.ToInsecureDecimal().Should().Be(99.99m); }

    [Fact]
    public void TryParse_valid() { CyDecimal.TryParse("42.5", out var r).Should().BeTrue(); using (r) { r!.ToInsecureDecimal().Should().Be(42.5m); } }

    [Fact]
    public void TryParse_invalid() { CyDecimal.TryParse("abc", out var r).Should().BeFalse(); r.Should().BeNull(); }

    [Fact]
    public void TryParse_span_valid() { CyDecimal.TryParse("1.5".AsSpan(), CultureInfo.InvariantCulture, out var r).Should().BeTrue(); using (r) { r!.ToInsecureDecimal().Should().Be(1.5m); } }

    [Fact]
    public void TryParse_span_invalid() { CyDecimal.TryParse("xyz".AsSpan(), CultureInfo.InvariantCulture, out var r).Should().BeFalse(); r.Should().BeNull(); }

    [Fact]
    public void MinValue_static() { using var cy = CyDecimal.MinValue; cy.ToInsecureDecimal().Should().Be(decimal.MinValue); }

    [Fact]
    public void MaxValue_static() { using var cy = CyDecimal.MaxValue; cy.ToInsecureDecimal().Should().Be(decimal.MaxValue); }

    [Fact]
    public void Zero_static() { using var cy = CyDecimal.Zero; cy.ToInsecureDecimal().Should().Be(0m); }

    [Fact]
    public void One_static() { using var cy = CyDecimal.One; cy.ToInsecureDecimal().Should().Be(1m); }

    [Fact]
    public void MinusOne_static() { using var cy = CyDecimal.MinusOne; cy.ToInsecureDecimal().Should().Be(-1m); }

    [Fact]
    public void CompareTo_null_returns_positive() { using var cy = new CyDecimal(1m); cy.CompareTo(null).Should().BePositive(); }

    [Fact]
    public void Dispose_throws() { var cy = new CyDecimal(1m); cy.Dispose(); var act = () => cy.ToInsecureDecimal(); act.Should().Throw<ObjectDisposedException>(); }

    [Fact]
    public void ToString_never_leaks() { using var cy = new CyDecimal(42m); cy.ToString().Should().Contain("Encrypted"); }

    [Fact]
    public void Null_equality()
    {
        using var a = new CyDecimal(1m);
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyDecimal?)null == null).Should().BeTrue();
    }

    [Fact]
    public void UnaryPlus_ReturnsNewInstanceWithSameValue()
    {
        using var a = new CyDecimal(42.5m);
        using var b = +a;
        b.ToInsecureDecimal().Should().Be(42.5m);
        b.InstanceId.Should().NotBe(a.InstanceId);
    }

    [Fact]
    public void UnaryMinus_ReturnsNegatedValue()
    {
        using var a = new CyDecimal(42.5m);
        using var b = -a;
        b.ToInsecureDecimal().Should().Be(-42.5m);
    }

    [Fact]
    public void Increment_ReturnsValuePlusOne()
    {
        var a = new CyDecimal(10m);
        using var b = ++a;
        b.ToInsecureDecimal().Should().Be(11m);
    }

    [Fact]
    public void Decrement_ReturnsValueMinusOne()
    {
        var a = new CyDecimal(10m);
        using var b = --a;
        b.ToInsecureDecimal().Should().Be(9m);
    }

    [Fact]
    public void UnaryOperators_PropagateTaint()
    {
        using var a = new CyDecimal(5m);
        a.MarkTainted();
        using var pos = +a;
        using var neg = -a;
        pos.IsTainted.Should().BeTrue();
        neg.IsTainted.Should().BeTrue();
    }
}
