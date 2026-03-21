using FluentAssertions;
using Xunit;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Tests.Unit.Policy;

public class PolicyResolverTests
{
    [Fact]
    public void Resolve_HigherSecurityArithmeticWins()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Performance, allowStrictCrossPolicy: true);

        result.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
    }

    [Fact]
    public void Resolve_HigherSecurityComparisonWins()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Performance, allowStrictCrossPolicy: true);

        result.Comparison.Should().Be(ComparisonMode.HmacBased);
    }

    [Fact]
    public void Resolve_HigherSecurityStringOperationsWins()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Performance, allowStrictCrossPolicy: true);

        result.StringOperations.Should().Be(StringOperationMode.SecureEnclave);
    }

    [Fact]
    public void Resolve_StricterTaintWins()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.Taint.Should().Be(TaintMode.Strict);
    }

    [Fact]
    public void Resolve_StandardTaintBeatsRelaxed()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.Taint.Should().Be(TaintMode.Standard);
    }

    [Fact]
    public void Resolve_MoreVerboseAuditWins()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.Audit.Should().Be(AuditLevel.AllOperations);
    }

    [Fact]
    public void Resolve_DecryptionsAndTransfersBeatsCompromiseOnly()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.Audit.Should().Be(AuditLevel.DecryptionsAndTransfers);
    }

    [Fact]
    public void Resolve_MoreFrequentKeyRotationWins_EveryNOperations()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.KeyRotation.Kind.Should().Be(KeyRotationKind.EveryNOperations);
        result.KeyRotation.Value.Should().Be(100);
    }

    [Fact]
    public void Resolve_AutomaticKeyRotationBeatsManual()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.KeyRotation.Kind.Should().Be(KeyRotationKind.EveryNOperations);
        result.KeyRotation.Value.Should().Be(1000);
    }

    [Fact]
    public void Resolve_StrongerMemoryProtectionWins()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.Memory.Should().Be(MemoryProtection.PinnedLockedReEncrypting);
    }

    [Fact]
    public void Resolve_PinnedLockedBeatsPinnedOnly()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.Memory.Should().Be(MemoryProtection.PinnedLocked);
    }

    [Fact]
    public void Resolve_SamePolicy_ReturnsSameReference()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Maximum);

        result.Should().BeSameAs(SecurityPolicy.Maximum);
    }

    [Fact]
    public void Resolve_MaxDecryptionCount_TakesMinimum()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.MaxDecryptionCount.Should().Be(10);
    }

    [Fact]
    public void Resolve_MaxDecryptionCount_TakesMinimum_BalancedVsPerformance()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.MaxDecryptionCount.Should().Be(100);
    }

    [Fact]
    public void Resolve_Name_IsFormattedAsResolved()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.Name.Should().Be("Resolved(Maximum+Balanced)");
    }

    [Fact]
    public void Resolve_Name_PreservesOrder()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Maximum, allowStrictCrossPolicy: true);

        result.Name.Should().Be("Resolved(Balanced+Maximum)");
    }

    [Fact]
    public void Resolve_NullLeft_ThrowsArgumentNullException()
    {
        var act = () => PolicyResolver.Resolve(null!, SecurityPolicy.Balanced);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Resolve_NullRight_ThrowsArgumentNullException()
    {
        var act = () => PolicyResolver.Resolve(SecurityPolicy.Balanced, null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Resolve_MaximumAndPerformance_TakesStrictestOfEach()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Performance, allowStrictCrossPolicy: true);

        result.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
        result.Comparison.Should().Be(ComparisonMode.HmacBased);
        result.StringOperations.Should().Be(StringOperationMode.SecureEnclave);
        result.Memory.Should().Be(MemoryProtection.PinnedLockedReEncrypting);
        result.Taint.Should().Be(TaintMode.Strict);
        result.Audit.Should().Be(AuditLevel.AllOperations);
        result.MaxDecryptionCount.Should().Be(10);
    }

    [Fact]
    public void Resolve_IsCommutative_ForComponentValues()
    {
        var ab = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);
        var ba = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Maximum, allowStrictCrossPolicy: true);

        ab.Arithmetic.Should().Be(ba.Arithmetic);
        ab.Comparison.Should().Be(ba.Comparison);
        ab.StringOperations.Should().Be(ba.StringOperations);
        ab.Memory.Should().Be(ba.Memory);
        ab.Taint.Should().Be(ba.Taint);
        ab.Audit.Should().Be(ba.Audit);
        ab.MaxDecryptionCount.Should().Be(ba.MaxDecryptionCount);
        ab.KeyRotation.Kind.Should().Be(ba.KeyRotation.Kind);
        ab.KeyRotation.Value.Should().Be(ba.KeyRotation.Value);
    }

    // === Rule 2: Strict taint cross-policy throws without explicit opt-in ===

    [Fact]
    public void Resolve_StrictTaintCrossPolicy_WithoutOptIn_ThrowsPolicyViolationException()
    {
        // Maximum has TaintMode.Strict; Balanced does not
        var act = () => PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced);

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*TaintMode.Strict*explicit cast*");
    }

    [Fact]
    public void Resolve_StrictTaintCrossPolicy_WithOptIn_Succeeds()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.Should().NotBeNull();
        result.Taint.Should().Be(TaintMode.Strict);
    }

    [Fact]
    public void Resolve_NonStrictPolicies_NoOptInRequired()
    {
        // Balanced (Standard) + Performance (Relaxed) — neither is Strict
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.Should().NotBeNull();
    }

    // === AutoDestroy / AllowDemotion resolution ===

    [Fact]
    public void Resolve_AutoDestroy_TrueIfEitherHasIt()
    {
        // Maximum has AutoDestroy=true, Balanced has AutoDestroy=false
        var result = PolicyResolver.Resolve(SecurityPolicy.Maximum, SecurityPolicy.Balanced, allowStrictCrossPolicy: true);

        result.AutoDestroy.Should().BeTrue();
    }

    [Fact]
    public void Resolve_AutoDestroy_FalseIfNeitherHasIt()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.AutoDestroy.Should().BeFalse();
    }

    [Fact]
    public void Resolve_AllowDemotion_FalseIfNeitherAllows()
    {
        var result = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        result.AllowDemotion.Should().BeFalse();
    }

    // === Explain() tests ===

    [Fact]
    public void Explain_ReturnsSameResolvedNameAsResolve()
    {
        var resolved = PolicyResolver.Resolve(SecurityPolicy.Balanced, SecurityPolicy.Performance);
        var explanation = PolicyResolver.Explain(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        explanation.ResolvedName.Should().Be(resolved.Name);
    }

    [Fact]
    public void Explain_ListsAllComponents()
    {
        var explanation = PolicyResolver.Explain(SecurityPolicy.Balanced, SecurityPolicy.Performance);

        explanation.Components.Should().NotBeEmpty();
        explanation.Components.Select(c => c.ComponentName).Should().Contain("Arithmetic");
        explanation.Components.Select(c => c.ComponentName).Should().Contain("Taint");
        explanation.Components.Select(c => c.ComponentName).Should().Contain("Memory");
        explanation.Components.Select(c => c.ComponentName).Should().Contain("Audit");
        explanation.Components.Select(c => c.ComponentName).Should().Contain("KeyRotation");
        explanation.Components.Select(c => c.ComponentName).Should().Contain("MaxDecryptionCount");
        explanation.Components.Select(c => c.ComponentName).Should().Contain("Overflow");
    }

    [Fact]
    public void Explain_ShowsCorrectResolutionForMixedPolicies()
    {
        var explanation = PolicyResolver.Explain(SecurityPolicy.Maximum, SecurityPolicy.Performance, allowStrictCrossPolicy: true);

        var arithmetic = explanation.Components.First(c => c.ComponentName == "Arithmetic");
        arithmetic.ResolvedValue.Should().Be(ArithmeticMode.SecureEnclave.ToString());
        arithmetic.Rule.Should().NotBeNullOrEmpty();

        var taint = explanation.Components.First(c => c.ComponentName == "Taint");
        taint.ResolvedValue.Should().Be(TaintMode.Strict.ToString());
    }
}
