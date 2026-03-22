using FluentAssertions;
using Xunit;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Tests.Unit.Policy;

public class SecurityPolicyBuilderTests
{
    [Fact]
    public void Build_WithAllSettings_CreatesCorrectPolicy()
    {
        var policy = new SecurityPolicyBuilder()
            .WithName("FullCustom")
            .WithArithmeticMode(ArithmeticMode.SecureEnclave)
            .WithComparisonMode(ComparisonMode.HmacBased)
            .WithStringOperationMode(StringOperationMode.SecureEnclave)
            .WithMemoryProtection(MemoryProtection.PinnedLockedReEncrypting)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(50))
            .WithAuditLevel(AuditLevel.AllOperations)
            .WithTaintMode(TaintMode.Strict)
            .WithMaxDecryptionCount(25)
            .WithAutoDestroy(true)
            .WithAllowDemotion(true)
            .WithOverflowMode(OverflowMode.Checked)
            .Build();

        policy.Name.Should().Be("FullCustom");
        policy.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
        policy.Comparison.Should().Be(ComparisonMode.HmacBased);
        policy.StringOperations.Should().Be(StringOperationMode.SecureEnclave);
        policy.Memory.Should().Be(MemoryProtection.PinnedLockedReEncrypting);
        policy.KeyRotation.Kind.Should().Be(KeyRotationKind.EveryNOperations);
        policy.KeyRotation.Value.Should().Be(50);
        policy.Audit.Should().Be(AuditLevel.AllOperations);
        policy.Taint.Should().Be(TaintMode.Strict);
        policy.MaxDecryptionCount.Should().Be(25);
        policy.AutoDestroy.Should().BeTrue();
        policy.AllowDemotion.Should().BeTrue();
        policy.Overflow.Should().Be(OverflowMode.Checked);
    }

    [Fact]
    public void Build_WithDefaults_CreatesBalancedLikePolicy()
    {
        var policy = new SecurityPolicyBuilder().Build();

        policy.Name.Should().Be("Custom");
        policy.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
        policy.Comparison.Should().Be(ComparisonMode.HmacBased);
        policy.StringOperations.Should().Be(StringOperationMode.SecureEnclave);
        policy.Memory.Should().Be(MemoryProtection.PinnedLocked);
        policy.KeyRotation.Kind.Should().Be(KeyRotationKind.EveryNOperations);
        policy.KeyRotation.Value.Should().Be(1000);
        policy.Audit.Should().Be(AuditLevel.DecryptionsAndTransfers);
        policy.Taint.Should().Be(TaintMode.Standard);
        policy.MaxDecryptionCount.Should().Be(100);
        policy.AutoDestroy.Should().BeFalse();
        policy.AllowDemotion.Should().BeFalse();
    }

    [Fact]
    public void Build_StrictTaintWithCompromiseOnlyAudit_ThrowsPolicyViolationException()
    {
        var builder = new SecurityPolicyBuilder()
            .WithTaintMode(TaintMode.Strict)
            .WithAuditLevel(AuditLevel.CompromiseOnly);

        var act = () => builder.Build();

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*Strict taint*");
    }

    [Fact]
    public void Build_StrictTaintWithNoneAudit_ThrowsPolicyViolationException()
    {
        var builder = new SecurityPolicyBuilder()
            .WithTaintMode(TaintMode.Strict)
            .WithAuditLevel(AuditLevel.None);

        var act = () => builder.Build();

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*Strict taint*");
    }

    [Fact]
    public void Build_PinnedLockedReEncryptingWithManualKeyRotation_ThrowsPolicyViolationException()
    {
        var builder = new SecurityPolicyBuilder()
            .WithMemoryProtection(MemoryProtection.PinnedLockedReEncrypting)
            .WithKeyRotation(KeyRotationPolicy.Manual);

        var act = () => builder.Build();

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*PinnedLockedReEncrypting*automatic key rotation*");
    }

    [Fact]
    public void Build_HomomorphicBasicArithmetic_WithPinnedLocked_Succeeds()
    {
        var policy = new SecurityPolicyBuilder()
            .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .Build();

        policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicBasic);
    }

    [Fact]
    public void Build_HomomorphicFullArithmetic_WithAllOperationsAudit_Succeeds()
    {
        var policy = new SecurityPolicyBuilder()
            .WithArithmeticMode(ArithmeticMode.HomomorphicFull)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithAuditLevel(AuditLevel.AllOperations)
            .Build();

        policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicFull);
    }

    [Fact]
    public void Build_HomomorphicFullArithmetic_WithoutAllOperationsAudit_ThrowsPolicyViolationException()
    {
        var builder = new SecurityPolicyBuilder()
            .WithArithmeticMode(ArithmeticMode.HomomorphicFull)
            .WithAuditLevel(AuditLevel.DecryptionsAndTransfers);

        var act = () => builder.Build();

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*HomomorphicFull*AllOperations*");
    }

    [Fact]
    public void Build_HomomorphicBasicArithmetic_WithPinnedOnly_ThrowsPolicyViolationException()
    {
        var builder = new SecurityPolicyBuilder()
            .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
            .WithMemoryProtection(MemoryProtection.PinnedOnly);

        var act = () => builder.Build();

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*PinnedLocked*");
    }

    [Fact]
    public void Build_HomomorphicCircuitComparison_WithoutFheArithmetic_ThrowsPolicyViolationException()
    {
        var builder = new SecurityPolicyBuilder()
            .WithComparisonMode(ComparisonMode.HomomorphicCircuit);

        var act = () => builder.Build();

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*HomomorphicBasic*");
    }

    [Fact]
    public void Build_HomomorphicCircuitComparison_WithFheArithmetic_Succeeds()
    {
        var builder = new SecurityPolicyBuilder()
            .WithComparisonMode(ComparisonMode.HomomorphicCircuit)
            .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
            .WithMemoryProtection(MemoryProtection.PinnedLocked);

        var policy = builder.Build();

        policy.Comparison.Should().Be(ComparisonMode.HomomorphicCircuit);
    }

    [Fact]
    public void Build_HomomorphicEqualityStringOps_WithWeakMemory_ThrowsPolicyViolationException()
    {
        var builder = new SecurityPolicyBuilder()
            .WithStringOperationMode(StringOperationMode.HomomorphicEquality)
            .WithMemoryProtection(MemoryProtection.PinnedOnly);

        var act = () => builder.Build();

        act.Should().Throw<PolicyViolationException>()
            .WithMessage("*PinnedLocked*");
    }

    [Fact]
    public void Build_HomomorphicEqualityStringOps_WithPinnedLocked_Succeeds()
    {
        var builder = new SecurityPolicyBuilder()
            .WithStringOperationMode(StringOperationMode.HomomorphicEquality)
            .WithMemoryProtection(MemoryProtection.PinnedLocked);

        var policy = builder.Build();

        policy.StringOperations.Should().Be(StringOperationMode.HomomorphicEquality);
    }

    [Fact]
    public void WithName_EmptyString_ThrowsArgumentException()
    {
        var builder = new SecurityPolicyBuilder();

        var act = () => builder.WithName("");

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void WithName_WhitespaceOnly_ThrowsArgumentException()
    {
        var builder = new SecurityPolicyBuilder();

        var act = () => builder.WithName("   ");

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void WithName_Null_ThrowsArgumentException()
    {
        var builder = new SecurityPolicyBuilder();

        var act = () => builder.WithName(null!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void WithMaxDecryptionCount_Zero_ThrowsArgumentOutOfRangeException()
    {
        var builder = new SecurityPolicyBuilder();

        var act = () => builder.WithMaxDecryptionCount(0);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WithMaxDecryptionCount_Negative_ThrowsArgumentOutOfRangeException()
    {
        var builder = new SecurityPolicyBuilder();

        var act = () => builder.WithMaxDecryptionCount(-5);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WithKeyRotation_Null_ThrowsArgumentNullException()
    {
        var builder = new SecurityPolicyBuilder();

        var act = () => builder.WithKeyRotation(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Build_FluentApi_ReturnsSelf()
    {
        var builder = new SecurityPolicyBuilder();

        var result = builder
            .WithName("Test")
            .WithArithmeticMode(ArithmeticMode.SecureEnclave)
            .WithComparisonMode(ComparisonMode.HmacBased)
            .WithStringOperationMode(StringOperationMode.SecureEnclave)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithKeyRotation(KeyRotationPolicy.EveryNOperations(500))
            .WithAuditLevel(AuditLevel.DecryptionsAndTransfers)
            .WithTaintMode(TaintMode.Standard)
            .WithMaxDecryptionCount(50)
            .WithAutoDestroy(false)
            .WithAllowDemotion(false);

        result.Should().BeSameAs(builder);
    }
}
