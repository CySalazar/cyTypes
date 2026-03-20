using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyIntTests
{
    [Fact]
    public void Constructor_encrypts_and_decrypts_roundtrip()
    {
        using var cy = new CyInt(42);
        cy.ToInsecureInt().Should().Be(42);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void Roundtrip_edge_values(int value)
    {
        using var cy = new CyInt(value);
        cy.ToInsecureInt().Should().Be(value);
    }

    [Fact]
    public void Default_policy_is_Balanced()
    {
        using var cy = new CyInt(1);
        cy.Policy.Should().BeSameAs(SecurityPolicy.Balanced);
    }

    [Fact]
    public void Explicit_policy_is_respected()
    {
        using var cy = new CyInt(1, SecurityPolicy.Performance);
        cy.Policy.Should().BeSameAs(SecurityPolicy.Performance);
    }

    [Fact]
    public void ToInsecureInt_marks_compromised()
    {
        using var cy = new CyInt(42);
        cy.IsCompromised.Should().BeFalse();

        _ = cy.ToInsecureInt();

        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void ToString_never_leaks_plaintext()
    {
        using var cy = new CyInt(42);
        var s = cy.ToString();

        s.Should().Contain("Encrypted");
        s.Should().NotContain("42");
    }

    [Fact]
    public void Implicit_conversion_from_int()
    {
        CyInt cy = 99;
        using (cy)
        {
            cy.ToInsecureInt().Should().Be(99);
            cy.Policy.Should().BeSameAs(SecurityPolicy.Balanced);
        }
    }

    [Fact]
    public void Explicit_conversion_to_int_marks_compromised()
    {
        using var cy = new CyInt(55);

        int raw = (int)cy;

        raw.Should().Be(55);
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Disposed_throws_ObjectDisposedException()
    {
        var cy = new CyInt(1);
        cy.Dispose();

        var act = () => cy.ToInsecureInt();
        act.Should().Throw<ObjectDisposedException>();
    }
}

public sealed class CyIntOperatorTests
{
    [Fact]
    public void Add_operator()
    {
        using var a = new CyInt(10);
        using var b = new CyInt(20);
        using var c = a + b;

        c.ToInsecureInt().Should().Be(30);
    }

    [Fact]
    public void Subtract_operator()
    {
        using var a = new CyInt(20);
        using var b = new CyInt(7);
        using var c = a - b;

        c.ToInsecureInt().Should().Be(13);
    }

    [Fact]
    public void Multiply_operator()
    {
        using var a = new CyInt(6);
        using var b = new CyInt(7);
        using var c = a * b;

        c.ToInsecureInt().Should().Be(42);
    }

    [Fact]
    public void Divide_operator()
    {
        using var a = new CyInt(100);
        using var b = new CyInt(4);
        using var c = a / b;

        c.ToInsecureInt().Should().Be(25);
    }

    [Fact]
    public void Modulo_operator()
    {
        using var a = new CyInt(17);
        using var b = new CyInt(5);
        using var c = a % b;

        c.ToInsecureInt().Should().Be(2);
    }

    [Fact]
    public void Equality_operator_same_value()
    {
        using var a = new CyInt(42);
        using var b = new CyInt(42);

        (a == b).Should().BeTrue();
        (a != b).Should().BeFalse();
    }

    [Fact]
    public void Equality_operator_different_values()
    {
        using var a = new CyInt(1);
        using var b = new CyInt(2);

        (a == b).Should().BeFalse();
        (a != b).Should().BeTrue();
    }

    [Fact]
    public void LessThan_operator()
    {
        using var a = new CyInt(5);
        using var b = new CyInt(10);

        (a < b).Should().BeTrue();
        (b < a).Should().BeFalse();
    }

    [Fact]
    public void GreaterThan_operator()
    {
        using var a = new CyInt(10);
        using var b = new CyInt(5);

        (a > b).Should().BeTrue();
        (b > a).Should().BeFalse();
    }

    [Fact]
    public void LessThanOrEqual_operator()
    {
        using var a = new CyInt(5);
        using var b = new CyInt(5);
        using var c = new CyInt(10);

        (a <= b).Should().BeTrue();
        (a <= c).Should().BeTrue();
        (c <= a).Should().BeFalse();
    }

    [Fact]
    public void GreaterThanOrEqual_operator()
    {
        using var a = new CyInt(10);
        using var b = new CyInt(10);
        using var c = new CyInt(5);

        (a >= b).Should().BeTrue();
        (a >= c).Should().BeTrue();
        (c >= a).Should().BeFalse();
    }

    [Fact]
    public void Arithmetic_result_inherits_higher_policy()
    {
        using var a = new CyInt(1, SecurityPolicy.Balanced);
        using var b = new CyInt(2, SecurityPolicy.Performance);
        using var c = a + b;

        // Balanced is higher security than Performance
        c.Policy.Arithmetic.Should().Be(a.Policy.Arithmetic);
    }

    [Fact]
    public void Taint_propagates_through_arithmetic()
    {
        using var a = new CyInt(1);
        a.MarkTainted();
        using var b = new CyInt(2);

        using var c = a + b;

        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Compromise_propagates_as_taint_through_arithmetic()
    {
        using var a = new CyInt(1);
        _ = a.ToInsecureInt(); // compromise a
        using var b = new CyInt(2);

        using var c = a + b;

        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Null_equality_checks()
    {
        using var a = new CyInt(1);

        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyInt?)null == null).Should().BeTrue();
    }

    [Fact]
    public void Checked_overflow_throws_on_addition()
    {
        using var a = new CyInt(int.MaxValue, SecurityPolicy.Maximum);
        using var b = new CyInt(1, SecurityPolicy.Maximum);

        var act = () => { using var _ = a + b; };

        act.Should().Throw<OverflowException>();
    }

    [Fact]
    public void Checked_overflow_throws_on_multiplication()
    {
        using var a = new CyInt(int.MaxValue, SecurityPolicy.Maximum);
        using var b = new CyInt(2, SecurityPolicy.Maximum);

        var act = () => { using var _ = a * b; };

        act.Should().Throw<OverflowException>();
    }

    [Fact]
    public void Unchecked_overflow_wraps_silently()
    {
        using var a = new CyInt(int.MaxValue, SecurityPolicy.Performance);
        using var b = new CyInt(1, SecurityPolicy.Performance);

        using var c = a + b;

        c.ToInsecureInt().Should().Be(int.MinValue);
    }

    [Fact]
    public void Custom_checked_policy_throws_on_overflow()
    {
        var policy = new SecurityPolicyBuilder()
            .WithOverflowMode(CyTypes.Core.Policy.Components.OverflowMode.Checked)
            .Build();

        using var a = new CyInt(int.MaxValue, policy);
        using var b = new CyInt(1, policy);

        var act = () => { using var _ = a + b; };

        act.Should().Throw<OverflowException>();
    }
}
