using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Integration;

/// <summary>
/// End-to-end integration tests that exercise multiple subsystems together:
/// encryption → operators → taint propagation → policy resolution → disposal.
/// </summary>
public sealed class EndToEndTests
{
    [Fact]
    public void Full_arithmetic_pipeline_across_policies()
    {
        // Setup: values with different policies
        using var revenue = new CyInt(1000, SecurityPolicy.Balanced);
        using var cost = new CyInt(400, SecurityPolicy.Performance);
        using var tax = new CyInt(120, SecurityPolicy.Balanced);

        // Multi-step arithmetic chain
        using var gross = revenue - cost;
        using var net = gross - tax;

        // Verify correctness
        net.ToInsecureInt().Should().Be(480);

        // Verify policy resolution (should pick higher = Balanced, both use SecureEnclave)
        net.Policy.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
    }

    [Fact]
    public void Mixed_type_workflow_with_taint_tracking()
    {
        // Simulate a financial calculation workflow
        using var price = new CyDecimal(99.99m);
        using var quantity = new CyInt(5);
        using var description = new CyString("Widget");
        using var isActive = new CyBool(true);

        // Each type roundtrips independently
        price.ToInsecureValue().Should().Be(99.99m);
        quantity.ToInsecureInt().Should().Be(5);
        description.ToInsecureString().Should().Be("Widget");
        isActive.ToInsecureBool().Should().Be(true);

        // All are now compromised
        price.IsCompromised.Should().BeTrue();
        quantity.IsCompromised.Should().BeTrue();
        description.IsCompromised.Should().BeTrue();
        isActive.IsCompromised.Should().BeTrue();

        // Arithmetic with compromised value taints result
        using var doubled = quantity + new CyInt(5);
        doubled.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void String_operations_preserve_encryption_through_chain()
    {
        using var original = new CyString("  Hello, World!  ");

        // Chain of string operations — each produces a new encrypted CyString
        using var trimmed = original.Trim();
        using var upper = trimmed.ToUpper();
        using var sub = upper.Substring(0, 5);

        sub.ToInsecureString().Should().Be("HELLO");

        // Original is unaffected
        original.ToInsecureString().Should().Be("  Hello, World!  ");

        // None are tainted (all clean operations)
        sub.IsTainted.Should().BeFalse();
    }

    [Fact]
    public void Policy_elevation_then_arithmetic()
    {
        using var a = new CyInt(10, SecurityPolicy.Performance);
        a.ElevatePolicy(SecurityPolicy.Balanced);

        using var b = new CyInt(20, SecurityPolicy.Performance);
        using var c = a + b;

        // Result inherits elevated policy (Balanced uses SecureEnclave)
        c.Policy.Arithmetic.Should().Be(ArithmeticMode.SecureEnclave);
        c.ToInsecureInt().Should().Be(30);
    }

    [Fact]
    public void Auto_destroy_prevents_further_operations()
    {
        var policy = new SecurityPolicyBuilder()
            .WithMaxDecryptionCount(3)
            .Build();

        var cy = new CyInt(42, policy);

        // Use up all allowed decryptions
        cy.ToInsecureInt().Should().Be(42); // 1
        cy.ToInsecureInt().Should().Be(42); // 2
        cy.ToInsecureInt().Should().Be(42); // 3 — triggers auto-destroy

        cy.IsDisposed.Should().BeTrue();

        // Further access throws
        var act = () => cy.ToInsecureInt();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Taint_chain_across_multiple_operations()
    {
        using var a = new CyInt(10);
        using var b = new CyInt(20);
        using var c = new CyInt(30);

        // a gets compromised
        _ = a.ToInsecureInt();

        // Taint propagates through chain
        using var ab = a + b; // tainted (a is compromised)
        using var abc = ab + c; // tainted (ab is tainted)

        ab.IsTainted.Should().BeTrue();
        abc.IsTainted.Should().BeTrue();

        // c itself stays clean
        c.IsTainted.Should().BeFalse();
        c.IsCompromised.Should().BeFalse();
    }

    [Fact]
    public void Dispose_all_types_cleanly()
    {
        var cyInt = new CyInt(42);
        var cyLong = new CyLong(123L);
        var cyDouble = new CyDouble(3.14);
        var cyDecimal = new CyDecimal(99.99m);
        var cyBool = new CyBool(true);
        var cyString = new CyString("test");
        var cyBytes = new CyBytes(new byte[] { 1, 2, 3 });
        var cyGuid = new CyGuid(Guid.NewGuid());

        // Dispose all
        cyInt.Dispose();
        cyLong.Dispose();
        cyDouble.Dispose();
        cyDecimal.Dispose();
        cyBool.Dispose();
        cyString.Dispose();
        cyBytes.Dispose();
        cyGuid.Dispose();

        // All report disposed
        cyInt.IsDisposed.Should().BeTrue();
        cyLong.IsDisposed.Should().BeTrue();
        cyDouble.IsDisposed.Should().BeTrue();
        cyDecimal.IsDisposed.Should().BeTrue();
        cyBool.IsDisposed.Should().BeTrue();
        cyString.IsDisposed.Should().BeTrue();
        cyBytes.IsDisposed.Should().BeTrue();
        cyGuid.IsDisposed.Should().BeTrue();

        // All throw on further access
        ((Func<int>)(() => cyInt.ToInsecureInt())).Should().Throw<ObjectDisposedException>();
        ((Func<string>)(() => cyString.ToInsecureString())).Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void SecurityBreached_event_fires_on_compromise()
    {
        using var cy = new CyInt(42);
        var eventFired = false;

        cy.SecurityBreached += (_, e) => eventFired = true;
        _ = cy.ToInsecureInt();

        eventFired.Should().BeTrue();
    }

    [Fact]
    public void PolicyChanged_event_fires_on_elevation()
    {
        using var cy = new CyInt(42, SecurityPolicy.Performance);
        var eventFired = false;

        cy.PolicyChanged += (_, e) => eventFired = true;
        cy.ElevatePolicy(SecurityPolicy.Balanced);

        eventFired.Should().BeTrue();
    }

    [Fact]
    public void CyBytes_roundtrip_preserves_exact_content()
    {
        var original = new byte[] { 0x00, 0xFF, 0x42, 0x80, 0x01 };
        using var cy = new CyBytes(original);

        var decrypted = cy.ToInsecureBytes();
        decrypted.Should().BeEquivalentTo(original);
    }

    [Fact]
    public void CyGuid_roundtrip_preserves_identity()
    {
        var original = Guid.NewGuid();
        using var cy = new CyGuid(original);

        cy.ToInsecureGuid().Should().Be(original);
    }

    [Fact]
    public void CyString_secure_comparison_does_not_compromise()
    {
        using var a = new CyString("secret");
        using var b = new CyString("secret");
        using var c = new CyString("other");

        a.SecureEquals(b).Should().BeTrue();
        a.SecureEquals(c).Should().BeFalse();

        // SecureEquals should not mark compromise
        a.IsCompromised.Should().BeFalse();
        b.IsCompromised.Should().BeFalse();
    }

    [Fact]
    public void ToString_never_leaks_plaintext_for_any_type()
    {
        using var cyInt = new CyInt(42);
        using var cyString = new CyString("secret");
        using var cyBool = new CyBool(true);
        using var cyDouble = new CyDouble(3.14);

        cyInt.ToString().Should().NotContain("42");
        cyString.ToString().Should().NotContain("secret");
        cyBool.ToString().Should().NotContain("True").And.NotContain("true");
        cyDouble.ToString().Should().NotContain("3.14");

        // All should contain "Encrypted"
        cyInt.ToString().Should().Contain("Encrypted");
        cyString.ToString().Should().Contain("Encrypted");
        cyBool.ToString().Should().Contain("Encrypted");
        cyDouble.ToString().Should().Contain("Encrypted");
    }

    [Fact]
    public void Builder_validation_rejects_invalid_policy_combinations()
    {
        // Strict taint + CompromiseOnly audit = invalid
        var act1 = () => new SecurityPolicyBuilder()
            .WithTaintMode(TaintMode.Strict)
            .WithAuditLevel(AuditLevel.CompromiseOnly)
            .Build();
        act1.Should().Throw<PolicyViolationException>();

        // PinnedLockedReEncrypting + Manual rotation = invalid
        var act2 = () => new SecurityPolicyBuilder()
            .WithMemoryProtection(MemoryProtection.PinnedLockedReEncrypting)
            .WithKeyRotation(KeyRotationPolicy.Manual)
            .Build();
        act2.Should().Throw<PolicyViolationException>();

        // FHE modes are rejected (Phase 3 not available)
        var act3 = () => new SecurityPolicyBuilder()
            .WithArithmeticMode(ArithmeticMode.HomomorphicFull)
            .Build();
        act3.Should().Throw<PolicyViolationException>();
    }
}
