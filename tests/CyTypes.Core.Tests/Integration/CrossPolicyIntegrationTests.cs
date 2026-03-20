using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Integration;

public sealed class CrossPolicyIntegrationTests
{
    [Fact]
    public void Arithmetic_between_different_policies_resolves_to_stricter()
    {
        using var a = new CyInt(10, SecurityPolicy.Performance);
        using var b = new CyInt(20, SecurityPolicy.Maximum);

        using var result = a + b;

        // PolicyResolver creates a merged policy with the stricter settings from each
        result.ToInsecureInt().Should().Be(30);
        result.Policy.MaxDecryptionCount.Should().BeLessOrEqualTo(SecurityPolicy.Maximum.MaxDecryptionCount);
    }

    [Fact]
    public void Taint_propagates_through_arithmetic()
    {
        using var clean = new CyInt(5);
        using var tainted = new CyInt(10);
        tainted.MarkTainted();

        using var result = clean + tainted;

        result.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void MarkCompromised_sets_flag_on_instance()
    {
        using var cy = new CyInt(42);

        cy.MarkCompromised();

        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void ElevatePolicy_throws_on_demotion()
    {
        using var cy = new CyInt(42, SecurityPolicy.Maximum);

        var act = () => cy.ElevatePolicy(SecurityPolicy.Performance);

        act.Should().Throw<PolicyViolationException>();
    }

    [Fact]
    public void ClearTaint_with_reason_clears_taint_flag()
    {
        using var cy = new CyInt(42);
        cy.MarkTainted();
        cy.IsTainted.Should().BeTrue();

        cy.ClearTaint("Verified by admin review");

        cy.IsTainted.Should().BeFalse();
    }
}
