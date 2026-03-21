using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Core.Security;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

internal sealed class TestCyType : CyTypeBase<TestCyType, int>
{
    public TestCyType(int value, SecurityPolicy? policy = null) : base(value, policy) { }
    internal TestCyType(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        : base(encryptedBytes, policy, clonedKeyManager) { }
    protected override byte[] SerializeValue(int value) => BitConverter.GetBytes(value);
    protected override int DeserializeValue(byte[] data) => BitConverter.ToInt32(data);
    protected override TestCyType CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager);

    /// <summary>Expose DecryptValue for testing.</summary>
    public int GetValue() => DecryptValue();
}

public sealed class CyTypeBaseTests
{
    [Fact]
    public void Encrypt_decrypt_roundtrip_preserves_value()
    {
        using var ct = new TestCyType(42);

        ct.GetValue().Should().Be(42);
    }

    [Fact]
    public void ToString_never_contains_plaintext_value_and_contains_Encrypted()
    {
        using var ct = new TestCyType(42);

        var str = ct.ToString();

        str.Should().NotContain("42");
        str.Should().Contain("Encrypted");
    }

    [Fact]
    public void ToString_includes_policy_name()
    {
        using var ct = new TestCyType(42);

        ct.ToString().Should().Contain(ct.Policy.Name);
    }

    [Fact]
    public void InstanceId_is_non_empty()
    {
        using var ct = new TestCyType(1);

        ct.InstanceId.Should().NotBe(Guid.Empty);
    }

    [Fact]
    public void CreatedUtc_is_approximately_now()
    {
        var before = DateTime.UtcNow;
        using var ct = new TestCyType(1);
        var after = DateTime.UtcNow;

        ct.CreatedUtc.Should().BeOnOrAfter(before);
        ct.CreatedUtc.Should().BeOnOrBefore(after);
    }

    [Fact]
    public void IsDisposed_false_initially_true_after_dispose()
    {
        var ct = new TestCyType(1);

        ct.IsDisposed.Should().BeFalse();

        ct.Dispose();

        ct.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Dispose_is_safe_to_call_twice()
    {
        var ct = new TestCyType(1);

        ct.Dispose();
        var act = () => ct.Dispose();

        act.Should().NotThrow();
    }

    [Fact]
    public void GetValue_throws_ObjectDisposedException_after_dispose()
    {
        var ct = new TestCyType(1);
        ct.Dispose();

        var act = () => ct.GetValue();

        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void IsCompromised_starts_false()
    {
        using var ct = new TestCyType(1);

        ct.IsCompromised.Should().BeFalse();
    }

    [Fact]
    public void MarkCompromised_sets_IsCompromised_true_and_fires_SecurityBreached_event()
    {
        using var ct = new TestCyType(1);
        SecurityEvent? firedEvent = null;
        ct.SecurityBreached += (_, e) => firedEvent = e;

        ct.MarkCompromised();

        ct.IsCompromised.Should().BeTrue();
        firedEvent.Should().NotBeNull();
        firedEvent!.EventType.Should().Be(SecurityEventType.Compromised);
    }

    [Fact]
    public void IsTainted_starts_false_MarkTainted_sets_true_ClearTaint_clears()
    {
        using var ct = new TestCyType(1);

        ct.IsTainted.Should().BeFalse();

        ct.MarkTainted();
        ct.IsTainted.Should().BeTrue();

        ct.ClearTaint("verified-clean");
        ct.IsTainted.Should().BeFalse();
    }

    [Fact]
    public void Auto_destroy_disposes_after_MaxDecryptionCount_reached()
    {
        var policy = new SecurityPolicyBuilder()
            .WithMaxDecryptionCount(3)
            .Build();

        var ct = new TestCyType(100, policy);

        ct.GetValue(); // 1
        ct.GetValue(); // 2
        ct.GetValue(); // 3 — triggers auto-destroy

        ct.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Different_instances_have_different_InstanceIds()
    {
        using var a = new TestCyType(1);
        using var b = new TestCyType(2);

        a.InstanceId.Should().NotBe(b.InstanceId);
    }

    [Fact]
    public void Uses_Balanced_policy_by_default()
    {
        using var ct = new TestCyType(1);

        ct.Policy.Should().BeSameAs(SecurityPolicy.Balanced);
    }

    // === ToInsecureValue ===

    [Fact]
    public void ToInsecureValue_returns_plaintext_and_marks_compromised()
    {
        using var ct = new TestCyType(42);

        var value = ct.ToInsecureValue();

        value.Should().Be(42);
        ct.IsCompromised.Should().BeTrue();
    }

    // === ElevatePolicy ===

    [Fact]
    public void ElevatePolicy_to_higher_security_succeeds()
    {
        using var ct = new TestCyType(1, SecurityPolicy.Performance);

        ct.ElevatePolicy(SecurityPolicy.Balanced);

        ct.Policy.Should().BeSameAs(SecurityPolicy.Balanced);
    }

    [Fact]
    public void ElevatePolicy_fires_PolicyChanged_event()
    {
        using var ct = new TestCyType(1, SecurityPolicy.Performance);
        SecurityEvent? firedEvent = null;
        ct.PolicyChanged += (_, e) => firedEvent = e;

        ct.ElevatePolicy(SecurityPolicy.Balanced);

        firedEvent.Should().NotBeNull();
        firedEvent!.EventType.Should().Be(SecurityEventType.PolicyChanged);
    }

    [Fact]
    public void ElevatePolicy_to_lower_security_throws_PolicyViolationException()
    {
        using var ct = new TestCyType(1, SecurityPolicy.Balanced);

        var act = () => ct.ElevatePolicy(SecurityPolicy.Performance);

        act.Should().Throw<PolicyViolationException>();
    }

    // === ApplyPolicy ===

    [Fact]
    public void ApplyPolicy_demotion_without_AllowDemotion_throws()
    {
        using var ct = new TestCyType(1, SecurityPolicy.Balanced);

        var act = () => ct.ApplyPolicy(SecurityPolicy.Performance);

        act.Should().Throw<PolicyViolationException>();
    }

    [Fact]
    public void ApplyPolicy_demotion_with_AllowDemotion_marks_tainted()
    {
        var demotable = new SecurityPolicyBuilder()
            .WithAllowDemotion(true)
            .Build();

        using var ct = new TestCyType(1, demotable);

        ct.ApplyPolicy(SecurityPolicy.Performance);

        ct.IsTainted.Should().BeTrue();
        ct.Policy.Should().BeSameAs(SecurityPolicy.Performance);
    }

    [Fact]
    public void ApplyPolicy_promotion_does_not_taint()
    {
        using var ct = new TestCyType(1, SecurityPolicy.Performance);

        ct.ApplyPolicy(SecurityPolicy.Balanced);

        ct.IsTainted.Should().BeFalse();
        ct.Policy.Should().BeSameAs(SecurityPolicy.Balanced);
    }

    [Fact]
    public void ClearTaint_event_fires_with_reason()
    {
        using var ct = new TestCyType(1);
        ct.MarkTainted();

        SecurityEvent? firedEvent = null;
        ct.TaintCleared += (_, e) => firedEvent = e;

        ct.ClearTaint("verified-clean");

        ct.IsTainted.Should().BeFalse();
        firedEvent.Should().NotBeNull();
        firedEvent!.EventType.Should().Be(SecurityEventType.TaintCleared);
        firedEvent.Description.Should().Contain("verified-clean");
    }

    // === RotateKeyAndReEncrypt ===

    [Fact]
    public void RotateKeyAndReEncrypt_preserves_value()
    {
        using var ct = new TestCyType(42);

        ct.RotateKeyAndReEncrypt();

        ct.GetValue().Should().Be(42);
    }

    [Fact]
    public void RotateKey_alias_preserves_value()
    {
        using var ct = new TestCyType(99);

        // RotateKey() is an alias for RotateKeyAndReEncrypt()
        ct.RotateKey();

        ct.GetValue().Should().Be(99);
    }

    [Fact]
    public void ReEncryptWithCurrentKey_without_rotation_preserves_value()
    {
        using var ct = new TestCyType(77);

        ct.ReEncryptWithCurrentKey();

        ct.GetValue().Should().Be(77);
    }

    [Fact]
    public void ReEncryptWithCurrentKey_on_disposed_throws()
    {
        var ct = new TestCyType(1);
        ct.Dispose();

        var act = () => ct.ReEncryptWithCurrentKey();

        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void RotateKey_on_disposed_throws()
    {
        var ct = new TestCyType(1);
        ct.Dispose();

        var act = () => ct.RotateKey();

        act.Should().Throw<ObjectDisposedException>();
    }
}

public sealed class ReEncryptWithCyIntTests
{
    [Fact]
    public void CyInt_RotateKeyAndReEncrypt_roundtrip()
    {
        using var ci = new CyInt(123);

        ci.RotateKeyAndReEncrypt();

        ci.ToInsecureInt().Should().Be(123);
    }
}

public sealed class CyTypeBaseAdditionalTests
{
    [Fact]
    public void ToSecureBytes_returns_non_empty_bytes()
    {
        using var ct = new TestCyType(42);
        var bytes = ct.ToSecureBytes();
        bytes.Should().NotBeEmpty();
    }

    [Fact]
    public void ToSecureBytes_on_disposed_throws()
    {
        var ct = new TestCyType(1);
        ct.Dispose();
        var act = () => ct.ToSecureBytes();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task DisposeAsync_disposes_instance()
    {
        var ct = new TestCyType(42);
        await ct.DisposeAsync();
        ct.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task DisposeAsync_is_idempotent()
    {
        var ct = new TestCyType(42);
        await ct.DisposeAsync();
        await ct.DisposeAsync();
        ct.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void ToString_IFormattable_returns_same_as_ToString()
    {
        using var ct = new TestCyType(42);
        IFormattable formattable = ct;
        formattable.ToString("N", null).Should().Be(ct.ToString());
    }

    [Fact]
    public void ApplyPolicy_fires_PolicyChanged_event()
    {
        using var ct = new TestCyType(1, SecurityPolicy.Performance);
        SecurityEvent? fired = null;
        ct.PolicyChanged += (_, e) => fired = e;

        ct.ApplyPolicy(SecurityPolicy.Balanced);

        fired.Should().NotBeNull();
        fired!.EventType.Should().Be(SecurityEventType.PolicyChanged);
    }

    [Fact]
    public void ElevatePolicy_null_throws()
    {
        using var ct = new TestCyType(1);
        var act = () => ct.ElevatePolicy(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ApplyPolicy_null_throws()
    {
        using var ct = new TestCyType(1);
        var act = () => ct.ApplyPolicy(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ElevatePolicy_on_disposed_throws()
    {
        var ct = new TestCyType(1);
        ct.Dispose();
        var act = () => ct.ElevatePolicy(SecurityPolicy.Maximum);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void ApplyPolicy_on_disposed_throws()
    {
        var ct = new TestCyType(1);
        ct.Dispose();
        var act = () => ct.ApplyPolicy(SecurityPolicy.Maximum);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void EncryptValue_on_disposed_throws()
    {
        var ct = new TestCyType(1);
        ct.Dispose();
        var act = () => ct.RotateKeyAndReEncrypt();
        act.Should().Throw<ObjectDisposedException>();
    }
}

public sealed class CloneTests
{
    [Fact]
    public void Clone_ReturnsNewInstanceWithSameDecryptedValue()
    {
        using var original = new TestCyType(42);
        using var clone = original.Clone();

        clone.GetValue().Should().Be(42);
    }

    [Fact]
    public void Clone_HasDifferentInstanceId()
    {
        using var original = new TestCyType(42);
        using var clone = original.Clone();

        clone.InstanceId.Should().NotBe(original.InstanceId);
    }

    [Fact]
    public void Clone_DoesNotMarkCompromised()
    {
        using var original = new TestCyType(42);
        using var clone = original.Clone();

        original.IsCompromised.Should().BeFalse();
        clone.IsCompromised.Should().BeFalse();
    }

    [Fact]
    public void Clone_PreservesPolicy()
    {
        using var original = new TestCyType(42, SecurityPolicy.Maximum);
        using var clone = original.Clone();

        clone.Policy.Should().BeSameAs(SecurityPolicy.Maximum);
    }

    [Fact]
    public void Clone_TaintNotPropagated()
    {
        using var original = new TestCyType(42);
        original.MarkTainted();

        using var clone = original.Clone();

        original.IsTainted.Should().BeTrue();
        clone.IsTainted.Should().BeFalse();
    }

    [Fact]
    public void Clone_OnDisposed_Throws()
    {
        var ct = new TestCyType(1);
        ct.Dispose();

        var act = () => ct.Clone();
        act.Should().Throw<ObjectDisposedException>();
    }
}
