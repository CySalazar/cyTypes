using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Integration;

public sealed class AutoDestroyIntegrationTests
{
    [Fact]
    public void Auto_destroy_disposes_after_max_decryptions()
    {
        // SecurityPolicy.Maximum has MaxDecryptionCount = 100
        // Use Maximum policy and exhaust decryptions
        var policy = new SecurityPolicyBuilder()
            .WithMaxDecryptionCount(3)
            .Build();
        using var cy = new CyInt(42, policy);

        // 3 decryptions should trigger auto-destroy
        cy.ToInsecureInt();
        cy.ToInsecureInt();
        cy.ToInsecureInt();

        cy.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Decryption_after_dispose_throws()
    {
        using var cy = new CyInt(42);
        cy.Dispose();

        var act = () => cy.ToInsecureInt();

        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Encrypt_decrypt_round_trip_for_all_primitive_types()
    {
        using var cyInt = new CyInt(42);
        using var cyLong = new CyLong(123456789L);
        using var cyFloat = new CyFloat(3.14f);
        using var cyDouble = new CyDouble(2.71828);
        using var cyDecimal = new CyDecimal(99.99m);
        using var cyBool = new CyBool(true);
        using var cyString = new CyString("hello");
        using var cyGuid = new CyGuid(Guid.Empty);
        var now = DateTime.UtcNow;
        using var cyDateTime = new CyDateTime(now);
        using var cyBytes = new CyBytes(new byte[] { 1, 2, 3 });

        cyInt.ToInsecureInt().Should().Be(42);
        cyLong.ToInsecureLong().Should().Be(123456789L);
        cyFloat.ToInsecureFloat().Should().Be(3.14f);
        cyDouble.ToInsecureDouble().Should().Be(2.71828);
        cyDecimal.ToInsecureDecimal().Should().Be(99.99m);
        cyBool.ToInsecureBool().Should().BeTrue();
        cyString.ToInsecureString().Should().Be("hello");
        cyGuid.ToInsecureGuid().Should().Be(Guid.Empty);
        cyDateTime.ToInsecureDateTime().Should().Be(now);
        cyBytes.ToInsecureBytes().Should().Equal(1, 2, 3);
    }
}
