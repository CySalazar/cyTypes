using System.Globalization;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyFloatTests
{
    [Theory]
    [InlineData(0f)]
    [InlineData(-1.5f)]
    [InlineData(3.14f)]
    [InlineData(float.MaxValue)]
    [InlineData(float.MinValue)]
    [InlineData(float.Epsilon)]
    public void Roundtrip_preserves_value(float value)
    {
        using var cy = new CyFloat(value);
        cy.ToInsecureFloat().Should().Be(value);
    }

    [Fact]
    public void Roundtrip_NaN()
    {
        using var cy = new CyFloat(float.NaN);
        float.IsNaN(cy.ToInsecureFloat()).Should().BeTrue();
    }

    [Fact]
    public void Roundtrip_PositiveInfinity()
    {
        using var cy = new CyFloat(float.PositiveInfinity);
        float.IsPositiveInfinity(cy.ToInsecureFloat()).Should().BeTrue();
    }

    [Fact]
    public void Roundtrip_NegativeInfinity()
    {
        using var cy = new CyFloat(float.NegativeInfinity);
        float.IsNegativeInfinity(cy.ToInsecureFloat()).Should().BeTrue();
    }

    [Fact]
    public void Implicit_conversion()
    {
        CyFloat cy = 3.14f;
        using (cy) { cy.ToInsecureFloat().Should().Be(3.14f); }
    }

    [Fact]
    public void Explicit_conversion_marks_compromised()
    {
        using var cy = new CyFloat(2.71f);
        float raw = (float)cy;
        raw.Should().Be(2.71f);
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Add_operator() { using var a = new CyFloat(1.5f); using var b = new CyFloat(2.5f); using var c = a + b; c.ToInsecureFloat().Should().Be(4.0f); }
    [Fact]
    public void Subtract_operator() { using var a = new CyFloat(5.0f); using var b = new CyFloat(2.0f); using var c = a - b; c.ToInsecureFloat().Should().Be(3.0f); }
    [Fact]
    public void Multiply_operator() { using var a = new CyFloat(3.0f); using var b = new CyFloat(4.0f); using var c = a * b; c.ToInsecureFloat().Should().Be(12.0f); }
    [Fact]
    public void Divide_operator() { using var a = new CyFloat(10.0f); using var b = new CyFloat(4.0f); using var c = a / b; c.ToInsecureFloat().Should().Be(2.5f); }
    [Fact]
    public void Modulo_operator() { using var a = new CyFloat(10.0f); using var b = new CyFloat(3.0f); using var c = a % b; c.ToInsecureFloat().Should().Be(1.0f); }

    [Fact]
    public void Equality_operators()
    {
        using var a = new CyFloat(3.14f);
        using var b = new CyFloat(3.14f);
        using var c = new CyFloat(2.71f);
        (a == b).Should().BeTrue();
        (a != c).Should().BeTrue();
    }

    [Fact]
    public void Null_equality()
    {
        using var a = new CyFloat(1.0f);
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyFloat?)null == null).Should().BeTrue();
    }

    [Fact]
    public void Comparison_operators()
    {
        using var a = new CyFloat(1.0f);
        using var b = new CyFloat(2.0f);
        (a < b).Should().BeTrue();
        (b > a).Should().BeTrue();
        (a <= b).Should().BeTrue();
        (b >= a).Should().BeTrue();
    }

    [Fact]
    public void Taint_propagates()
    {
        using var a = new CyFloat(1.0f); a.MarkTainted();
        using var b = new CyFloat(2.0f);
        using var c = a + b;
        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void NaN_not_equal_to_NaN()
    {
        using var a = new CyFloat(float.NaN);
        using var b = new CyFloat(float.NaN);
        (a == b).Should().BeFalse();
    }

    [Fact]
    public void NegativeZero_roundtrip()
    {
        using var cy = new CyFloat(-0.0f);
        var value = cy.ToInsecureFloat();
        (1.0f / value).Should().Be(float.NegativeInfinity);
    }

    [Fact]
    public void Parse_string() { using var cy = CyFloat.Parse("3.14", CultureInfo.InvariantCulture); cy.ToInsecureFloat().Should().Be(3.14f); }

    [Fact]
    public void Parse_span() { using var cy = CyFloat.Parse("3.14".AsSpan(), CultureInfo.InvariantCulture); cy.ToInsecureFloat().Should().Be(3.14f); }

    [Fact]
    public void TryParse_valid() { CyFloat.TryParse("2.5", out var r).Should().BeTrue(); using (r) { r!.ToInsecureFloat().Should().Be(2.5f); } }

    [Fact]
    public void TryParse_invalid() { CyFloat.TryParse("abc", out var r).Should().BeFalse(); r.Should().BeNull(); }

    [Fact]
    public void TryParse_span_valid() { CyFloat.TryParse("1.5".AsSpan(), CultureInfo.InvariantCulture, out var r).Should().BeTrue(); using (r) { r!.ToInsecureFloat().Should().Be(1.5f); } }

    [Fact]
    public void TryParse_span_invalid() { CyFloat.TryParse("xyz".AsSpan(), CultureInfo.InvariantCulture, out var r).Should().BeFalse(); r.Should().BeNull(); }

    [Fact]
    public void MinValue_static() { using var cy = CyFloat.MinValue; cy.ToInsecureFloat().Should().Be(float.MinValue); }

    [Fact]
    public void MaxValue_static() { using var cy = CyFloat.MaxValue; cy.ToInsecureFloat().Should().Be(float.MaxValue); }

    [Fact]
    public void PositiveInfinity_static() { using var cy = CyFloat.PositiveInfinity; float.IsPositiveInfinity(cy.ToInsecureFloat()).Should().BeTrue(); }

    [Fact]
    public void NegativeInfinity_static() { using var cy = CyFloat.NegativeInfinity; float.IsNegativeInfinity(cy.ToInsecureFloat()).Should().BeTrue(); }

    [Fact]
    public void NaN_static() { using var cy = CyFloat.NaN; float.IsNaN(cy.ToInsecureFloat()).Should().BeTrue(); }

    [Fact]
    public void Epsilon_static() { using var cy = CyFloat.Epsilon; cy.ToInsecureFloat().Should().Be(float.Epsilon); }

    [Fact]
    public void CompareTo_null_returns_positive() { using var cy = new CyFloat(1.0f); cy.CompareTo(null).Should().BePositive(); }

    [Fact]
    public void Dispose_throws() { var cy = new CyFloat(1.0f); cy.Dispose(); var act = () => cy.ToInsecureFloat(); act.Should().Throw<ObjectDisposedException>(); }

    [Fact]
    public void ToString_never_leaks() { using var cy = new CyFloat(3.14f); cy.ToString().Should().Contain("Encrypted"); }
}
