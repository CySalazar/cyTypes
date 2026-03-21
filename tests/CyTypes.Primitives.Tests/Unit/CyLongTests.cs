using System.Globalization;
using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyLongTests
{
    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    [InlineData(42L)]
    public void Roundtrip_preserves_value(long value)
    {
        using var cy = new CyLong(value);
        cy.ToInsecureLong().Should().Be(value);
    }

    [Fact]
    public void Implicit_conversion_from_long()
    {
        CyLong cy = 100L;
        using (cy) { cy.ToInsecureLong().Should().Be(100L); }
    }

    [Fact]
    public void Explicit_conversion_to_long_marks_compromised()
    {
        using var cy = new CyLong(55L);
        long raw = (long)cy;
        raw.Should().Be(55L);
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Add_operator() { using var a = new CyLong(10L); using var b = new CyLong(20L); using var c = a + b; c.ToInsecureLong().Should().Be(30L); }
    [Fact]
    public void Subtract_operator() { using var a = new CyLong(20L); using var b = new CyLong(7L); using var c = a - b; c.ToInsecureLong().Should().Be(13L); }
    [Fact]
    public void Multiply_operator() { using var a = new CyLong(6L); using var b = new CyLong(7L); using var c = a * b; c.ToInsecureLong().Should().Be(42L); }
    [Fact]
    public void Divide_operator() { using var a = new CyLong(100L); using var b = new CyLong(4L); using var c = a / b; c.ToInsecureLong().Should().Be(25L); }
    [Fact]
    public void Modulo_operator() { using var a = new CyLong(17L); using var b = new CyLong(5L); using var c = a % b; c.ToInsecureLong().Should().Be(2L); }

    [Fact]
    public void Equality_operators()
    {
        using var a = new CyLong(42L);
        using var b = new CyLong(42L);
        using var c = new CyLong(99L);
        (a == b).Should().BeTrue();
        (a != c).Should().BeTrue();
    }

    [Fact]
    public void Comparison_operators()
    {
        using var a = new CyLong(5L);
        using var b = new CyLong(10L);
        (a < b).Should().BeTrue();
        (b > a).Should().BeTrue();
        (a <= b).Should().BeTrue();
        (b >= a).Should().BeTrue();
    }

    [Fact]
    public void Taint_propagates()
    {
        using var a = new CyLong(1L); a.MarkTainted();
        using var b = new CyLong(2L);
        using var c = a + b;
        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void ToString_never_leaks_plaintext()
    {
        using var cy = new CyLong(42L);
        cy.ToString().Should().Contain("Encrypted").And.NotContain("42");
    }

    [Fact]
    public void Parse_string_creates_correct_value()
    {
        using var cy = CyLong.Parse("12345", CultureInfo.InvariantCulture);
        cy.ToInsecureLong().Should().Be(12345L);
    }

    [Fact]
    public void Parse_span_creates_correct_value()
    {
        using var cy = CyLong.Parse("12345".AsSpan(), CultureInfo.InvariantCulture);
        cy.ToInsecureLong().Should().Be(12345L);
    }

    [Fact]
    public void TryParse_valid_string_returns_true()
    {
        CyLong.TryParse("999", out var result).Should().BeTrue();
        using (result) { result!.ToInsecureLong().Should().Be(999L); }
    }

    [Fact]
    public void TryParse_invalid_string_returns_false()
    {
        CyLong.TryParse("abc", out var result).Should().BeFalse();
        result.Should().BeNull();
    }

    [Fact]
    public void TryParse_span_valid_returns_true()
    {
        CyLong.TryParse("777".AsSpan(), null, out var result).Should().BeTrue();
        using (result) { result!.ToInsecureLong().Should().Be(777L); }
    }

    [Fact]
    public void TryParse_span_invalid_returns_false()
    {
        CyLong.TryParse("xyz".AsSpan(), null, out var result).Should().BeFalse();
        result.Should().BeNull();
    }

    [Fact]
    public void MinValue_returns_long_MinValue()
    {
        using var cy = CyLong.MinValue;
        cy.ToInsecureLong().Should().Be(long.MinValue);
    }

    [Fact]
    public void MaxValue_returns_long_MaxValue()
    {
        using var cy = CyLong.MaxValue;
        cy.ToInsecureLong().Should().Be(long.MaxValue);
    }

    [Fact]
    public void CompareTo_null_returns_positive()
    {
        using var cy = new CyLong(1L);
        cy.CompareTo(null).Should().BePositive();
    }

    [Fact]
    public void Dispose_makes_ToInsecure_throw()
    {
        var cy = new CyLong(42L);
        cy.Dispose();
        var act = () => cy.ToInsecureLong();
        act.Should().Throw<ObjectDisposedException>();
    }
}
