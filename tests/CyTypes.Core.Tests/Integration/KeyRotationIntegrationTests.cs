using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Integration;

public sealed class KeyRotationIntegrationTests
{
    [Fact]
    public void Key_rotation_preserves_value_after_re_encryption()
    {
        using var cy = new CyInt(42);
        var originalValue = cy.ToInsecureInt();

        cy.RotateKeyAndReEncrypt();

        var afterRotation = cy.ToInsecureInt();
        afterRotation.Should().Be(originalValue);
    }

    [Fact]
    public void Key_rotation_changes_secure_bytes_representation()
    {
        using var cy = new CyInt(99);
        var before = cy.ToSecureBytes();

        cy.RotateKeyAndReEncrypt();

        var after = cy.ToSecureBytes();
        after.Should().NotEqual(before);
    }

    [Fact]
    public void Key_rotation_on_CyString_preserves_value()
    {
        using var cy = new CyString("sensitive data");
        cy.RotateKeyAndReEncrypt();
        cy.ToInsecureString().Should().Be("sensitive data");
    }

    [Fact]
    public void Multiple_key_rotations_preserve_value()
    {
        using var cy = new CyDouble(3.14159);

        for (int i = 0; i < 5; i++)
            cy.RotateKeyAndReEncrypt();

        cy.ToInsecureDouble().Should().Be(3.14159);
    }

    [Fact]
    public void Key_rotation_increments_secure_bytes_envelope_key_id()
    {
        using var cy = new CyInt(1);
        var before = cy.ToSecureBytes();
        var keyIdBefore = new Guid(before.AsSpan(1, 16));

        cy.RotateKeyAndReEncrypt();

        var after = cy.ToSecureBytes();
        var keyIdAfter = new Guid(after.AsSpan(1, 16));

        keyIdAfter.Should().NotBe(keyIdBefore);
    }
}
