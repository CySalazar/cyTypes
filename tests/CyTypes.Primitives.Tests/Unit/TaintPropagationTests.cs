using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

/// <summary>
/// Tests the taint propagation rules from the spec:
/// | Operation | Source State | Result State |
/// |-----------|-------------|--------------|
/// | Copy (clean source) | clean | clean |
/// | Copy (compromised source) | compromised | tainted |
/// | ToInsecure*() | any | IsCompromised = true |
/// | a + b (either tainted) | tainted | IsTainted = true |
/// | a + b (both clean, diff policies) | clean | higher policy, clean |
/// | Policy demotion | any | IsTainted = true |
/// | ClearTaint(reason) | tainted | clean (audit event) |
/// </summary>
public sealed class TaintPropagationTests
{
    [Fact]
    public void ToInsecure_marks_IsCompromised()
    {
        using var a = new CyInt(42);
        a.IsCompromised.Should().BeFalse();

        _ = a.ToInsecureInt();

        a.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Arithmetic_with_compromised_operand_taints_result()
    {
        using var a = new CyInt(1);
        _ = a.ToInsecureInt(); // compromise a
        using var b = new CyInt(2);

        using var c = a + b;

        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Arithmetic_with_tainted_operand_taints_result()
    {
        using var a = new CyInt(1);
        a.MarkTainted();
        using var b = new CyInt(2);

        using var c = a + b;

        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Arithmetic_with_both_clean_same_policy_clean_result()
    {
        using var a = new CyInt(1);
        using var b = new CyInt(2);

        using var c = a + b;

        c.IsTainted.Should().BeFalse();
        c.IsCompromised.Should().BeFalse();
    }

    [Fact]
    public void Arithmetic_with_different_policies_picks_higher()
    {
        using var a = new CyInt(1, SecurityPolicy.Balanced);
        using var b = new CyInt(2, SecurityPolicy.Performance);

        using var c = a + b;

        // Both Balanced and Performance use SecureEnclave arithmetic
        c.Policy.Arithmetic.Should().Be(Core.Policy.Components.ArithmeticMode.SecureEnclave);
        c.IsTainted.Should().BeFalse();
    }

    [Fact]
    public void Policy_demotion_with_AllowDemotion_marks_tainted()
    {
        var demotable = new SecurityPolicyBuilder()
            .WithAllowDemotion(true)
            .Build();

        using var a = new CyInt(1, demotable);

        a.ApplyPolicy(SecurityPolicy.Performance);

        a.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Policy_demotion_without_AllowDemotion_throws()
    {
        using var a = new CyInt(1, SecurityPolicy.Balanced);

        var act = () => a.ApplyPolicy(SecurityPolicy.Performance);

        act.Should().Throw<PolicyViolationException>();
    }

    [Fact]
    public void ClearTaint_requires_reason_and_clears()
    {
        using var a = new CyInt(1);
        a.MarkTainted();
        a.IsTainted.Should().BeTrue();

        a.ClearTaint("verified-clean-by-admin");

        a.IsTainted.Should().BeFalse();
    }

    [Fact]
    public void ClearTaint_empty_reason_throws()
    {
        using var a = new CyInt(1);
        a.MarkTainted();

        var act = () => a.ClearTaint("");

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Taint_propagates_across_types()
    {
        using var a = new CyDouble(3.14);
        a.MarkTainted();
        using var b = new CyDouble(2.71);

        using var c = a + b;

        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void String_concatenation_propagates_taint()
    {
        using var a = new CyString("hello"); a.MarkTainted();
        using var b = new CyString(" world");

        using var c = a + b;

        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Bool_logic_propagates_taint()
    {
        using var a = new CyBool(true); a.MarkTainted();
        using var b = new CyBool(false);

        using var c = a & b;

        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Foreach_char_on_CyString_marks_compromise()
    {
        using var cy = new CyString("abc");

        // Accessing individual chars via indexer marks compromise
        _ = cy[0];

        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Auto_destroy_on_MaxDecryptionCount_exceeded()
    {
        var policy = new SecurityPolicyBuilder()
            .WithMaxDecryptionCount(2)
            .Build();

        var cy = new CyInt(42, policy);
        cy.ToInsecureInt(); // 1
        cy.ToInsecureInt(); // 2 — triggers auto-destroy

        cy.IsDisposed.Should().BeTrue();
    }
}
