using CyTypes.Core.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.KeyManagement;

public sealed class FheKeyManagerTests
{
    [Fact]
    public void IsInitialized_defaults_to_false()
    {
        var mgr = new FheKeyManager();
        mgr.IsInitialized.Should().BeFalse();
    }

    [Fact]
    public void Initialize_sets_IsInitialized_to_true()
    {
        var mgr = new FheKeyManager();
        mgr.Initialize();
        mgr.IsInitialized.Should().BeTrue();
    }

    [Fact]
    public void Initialize_is_idempotent()
    {
        var mgr = new FheKeyManager();
        mgr.Initialize();
        mgr.Initialize();
        mgr.IsInitialized.Should().BeTrue();
    }
}
