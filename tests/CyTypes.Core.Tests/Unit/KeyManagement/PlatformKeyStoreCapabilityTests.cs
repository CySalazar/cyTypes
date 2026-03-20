using System.Runtime.InteropServices;
using System.Security;
using CyTypes.Core.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.KeyManagement;

public sealed class PlatformKeyStoreCapabilityTests
{
    [Fact]
    public void InMemoryKeyStore_Capability_is_InMemoryOnly()
    {
        var store = new InMemoryKeyStore();

        store.Capability.Should().Be(KeyStoreCapability.InMemoryOnly);
    }

    [Fact]
    public void PlatformKeyStoreFactory_Create_with_minimum_InMemoryOnly_does_not_throw()
    {
        var act = () => PlatformKeyStoreFactory.Create(minimumCapability: KeyStoreCapability.InMemoryOnly);

        act.Should().NotThrow();
    }

    [Fact]
    public void PlatformKeyStoreFactory_Create_with_minimum_HardwareBacked_throws_SecurityException_on_non_macOS()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // On macOS, HardwareBacked might actually be available via Keychain,
            // so skip this test on that platform.
            return;
        }

        var act = () => PlatformKeyStoreFactory.Create(minimumCapability: KeyStoreCapability.HardwareBacked);

        act.Should().Throw<SecurityException>();
    }
}
