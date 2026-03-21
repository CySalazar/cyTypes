using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyBoolTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Roundtrip_preserves_value(bool value)
    {
        using var cy = new CyBool(value);
        cy.ToInsecureBool().Should().Be(value);
    }

    [Fact]
    public void Implicit_conversion() { CyBool cy = true; using (cy) { cy.ToInsecureBool().Should().BeTrue(); } }

    [Fact]
    public void Explicit_conversion_marks_compromised()
    {
        using var cy = new CyBool(true);
        bool raw = (bool)cy;
        raw.Should().BeTrue();
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void ToString_never_leaks_plaintext()
    {
        using var cy = new CyBool(true);
        cy.ToString().Should().Contain("Encrypted").And.NotContain("True");
    }
}

public sealed class CyBoolLogicTests
{
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, false)]
    public void And_operator(bool a, bool b, bool expected)
    {
        using var ca = new CyBool(a);
        using var cb = new CyBool(b);
        using var result = ca & cb;
        result.ToInsecureBool().Should().Be(expected);
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    [InlineData(false, false, false)]
    public void Or_operator(bool a, bool b, bool expected)
    {
        using var ca = new CyBool(a);
        using var cb = new CyBool(b);
        using var result = ca | cb;
        result.ToInsecureBool().Should().Be(expected);
    }

    [Theory]
    [InlineData(true, true, false)]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    [InlineData(false, false, false)]
    public void Xor_operator(bool a, bool b, bool expected)
    {
        using var ca = new CyBool(a);
        using var cb = new CyBool(b);
        using var result = ca ^ cb;
        result.ToInsecureBool().Should().Be(expected);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Not_operator(bool input, bool expected)
    {
        using var cy = new CyBool(input);
        using var result = !cy;
        result.ToInsecureBool().Should().Be(expected);
    }

    [Fact]
    public void Equality_operators()
    {
        using var a = new CyBool(true);
        using var b = new CyBool(true);
        using var c = new CyBool(false);
        (a == b).Should().BeTrue();
        (a != c).Should().BeTrue();
    }

    [Fact]
    public void Taint_propagates_through_logic_ops()
    {
        using var a = new CyBool(true); a.MarkTainted();
        using var b = new CyBool(false);
        using var c = a & b;
        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Not_propagates_taint()
    {
        using var a = new CyBool(true); a.MarkTainted();
        using var b = !a;
        b.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void CompareTo_null_returns_positive()
    {
        using var cy = new CyBool(true);
        cy.CompareTo(null).Should().BePositive();
    }

    [Fact]
    public void CompareTo_false_less_than_true()
    {
        using var f = new CyBool(false);
        using var t = new CyBool(true);
        f.CompareTo(t).Should().BeNegative();
    }

    [Fact]
    public void Null_equality()
    {
        using var a = new CyBool(true);
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyBool?)null == null).Should().BeTrue();
    }

    [Fact]
    public void Dispose_throws()
    {
        var cy = new CyBool(true);
        cy.Dispose();
        var act = () => cy.ToInsecureBool();
        act.Should().Throw<ObjectDisposedException>();
    }
}
