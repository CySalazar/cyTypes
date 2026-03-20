using FluentAssertions;
using Xunit;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Tests.Unit.Policy;

public class SecurityPolicyTests
{
    [Fact]
    public void Maximum_HasCorrectArithmeticMode()
    {
        SecurityPolicy.Maximum.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
    }

    [Fact]
    public void Maximum_HasCorrectComparisonMode()
    {
        SecurityPolicy.Maximum.Comparison.Should().Be(ComparisonMode.HmacBased);
    }

    [Fact]
    public void Maximum_HasCorrectStringOperationMode()
    {
        SecurityPolicy.Maximum.StringOperations.Should().Be(StringOperationMode.SecureEnclave);
    }

    [Fact]
    public void Maximum_HasCorrectMemoryProtection()
    {
        SecurityPolicy.Maximum.Memory.Should().Be(MemoryProtection.PinnedLockedReEncrypting);
    }

    [Fact]
    public void Maximum_HasCorrectAuditLevel()
    {
        SecurityPolicy.Maximum.Audit.Should().Be(AuditLevel.AllOperations);
    }

    [Fact]
    public void Maximum_HasCorrectTaintMode()
    {
        SecurityPolicy.Maximum.Taint.Should().Be(TaintMode.Strict);
    }

    [Fact]
    public void Maximum_HasCorrectMaxDecryptionCount()
    {
        SecurityPolicy.Maximum.MaxDecryptionCount.Should().Be(10);
    }

    [Fact]
    public void Maximum_HasCorrectName()
    {
        SecurityPolicy.Maximum.Name.Should().Be("Maximum");
    }

    [Fact]
    public void Maximum_HasAutoDestroyEnabled()
    {
        SecurityPolicy.Maximum.AutoDestroy.Should().BeTrue();
    }

    [Fact]
    public void Maximum_HasAllowDemotionDisabled()
    {
        SecurityPolicy.Maximum.AllowDemotion.Should().BeFalse();
    }

    [Fact]
    public void Balanced_HasCorrectArithmeticMode()
    {
        SecurityPolicy.Balanced.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
    }

    [Fact]
    public void Balanced_HasCorrectComparisonMode()
    {
        SecurityPolicy.Balanced.Comparison.Should().Be(ComparisonMode.HmacBased);
    }

    [Fact]
    public void Balanced_HasCorrectStringOperationMode()
    {
        SecurityPolicy.Balanced.StringOperations.Should().Be(StringOperationMode.SecureEnclave);
    }

    [Fact]
    public void Balanced_HasCorrectMemoryProtection()
    {
        SecurityPolicy.Balanced.Memory.Should().Be(MemoryProtection.PinnedLocked);
    }

    [Fact]
    public void Balanced_HasCorrectAuditLevel()
    {
        SecurityPolicy.Balanced.Audit.Should().Be(AuditLevel.DecryptionsAndTransfers);
    }

    [Fact]
    public void Balanced_HasCorrectTaintMode()
    {
        SecurityPolicy.Balanced.Taint.Should().Be(TaintMode.Standard);
    }

    [Fact]
    public void Balanced_HasCorrectMaxDecryptionCount()
    {
        SecurityPolicy.Balanced.MaxDecryptionCount.Should().Be(100);
    }

    [Fact]
    public void Balanced_HasCorrectName()
    {
        SecurityPolicy.Balanced.Name.Should().Be("Balanced");
    }

    [Fact]
    public void Balanced_HasAutoDestroyDisabled()
    {
        SecurityPolicy.Balanced.AutoDestroy.Should().BeFalse();
    }

    [Fact]
    public void Balanced_HasAllowDemotionDisabled()
    {
        SecurityPolicy.Balanced.AllowDemotion.Should().BeFalse();
    }

    [Fact]
    public void Performance_HasCorrectArithmeticMode()
    {
        SecurityPolicy.Performance.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
    }

    [Fact]
    public void Performance_HasCorrectComparisonMode()
    {
        SecurityPolicy.Performance.Comparison.Should().Be(ComparisonMode.SecureEnclave);
    }

    [Fact]
    public void Performance_HasCorrectStringOperationMode()
    {
        SecurityPolicy.Performance.StringOperations.Should().Be(StringOperationMode.SecureEnclave);
    }

    [Fact]
    public void Performance_HasCorrectMemoryProtection()
    {
        SecurityPolicy.Performance.Memory.Should().Be(MemoryProtection.PinnedOnly);
    }

    [Fact]
    public void Performance_HasCorrectAuditLevel()
    {
        SecurityPolicy.Performance.Audit.Should().Be(AuditLevel.CompromiseOnly);
    }

    [Fact]
    public void Performance_HasCorrectTaintMode()
    {
        SecurityPolicy.Performance.Taint.Should().Be(TaintMode.Relaxed);
    }

    [Fact]
    public void Performance_HasCorrectMaxDecryptionCount()
    {
        SecurityPolicy.Performance.MaxDecryptionCount.Should().Be(int.MaxValue);
    }

    [Fact]
    public void Performance_HasCorrectName()
    {
        SecurityPolicy.Performance.Name.Should().Be("Performance");
    }

    [Fact]
    public void Performance_HasAutoDestroyDisabled()
    {
        SecurityPolicy.Performance.AutoDestroy.Should().BeFalse();
    }

    [Fact]
    public void Performance_HasAllowDemotionDisabled()
    {
        SecurityPolicy.Performance.AllowDemotion.Should().BeFalse();
    }

    [Fact]
    public void Default_ReturnsSameInstanceAsBalanced()
    {
        SecurityPolicy.Default.Should().BeSameAs(SecurityPolicy.Balanced);
    }

    [Fact]
    public void Properties_AreReadonly()
    {
        var policyType = typeof(SecurityPolicy);

        policyType.GetProperty(nameof(SecurityPolicy.Name))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.Arithmetic))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.Comparison))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.StringOperations))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.Memory))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.KeyRotation))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.Audit))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.Taint))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.MaxDecryptionCount))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.AutoDestroy))!.SetMethod.Should().BeNull();
        policyType.GetProperty(nameof(SecurityPolicy.AllowDemotion))!.SetMethod.Should().BeNull();
    }

    [Fact]
    public void SecurityPolicy_IsSealed()
    {
        typeof(SecurityPolicy).Should().BeSealed();
    }

    [Fact]
    public void ToString_ReturnsName()
    {
        SecurityPolicy.Maximum.ToString().Should().Be("Maximum");
        SecurityPolicy.Balanced.ToString().Should().Be("Balanced");
        SecurityPolicy.Performance.ToString().Should().Be("Performance");
    }
}
