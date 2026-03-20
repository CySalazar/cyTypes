using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class SealKeyManagerTests
{
    [Fact]
    public void Initialize_creates_context_and_keys()
    {
        using var km = new SealKeyManager();
        km.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());

        km.IsInitialized.Should().BeTrue();
        km.Context.Should().NotBeNull();
        km.PublicKey.Should().NotBeNull();
        km.SecretKey.Should().NotBeNull();
        km.RelinKeys.Should().NotBeNull();
    }

    [Fact]
    public void Initialize_twice_throws()
    {
        using var km = new SealKeyManager();
        km.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());

        var act = () => km.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Initialize_CKKS_throws_NotSupportedException()
    {
        using var km = new SealKeyManager();

        var act = () => km.Initialize(FheScheme.CKKS, SealParameterPresets.Bfv128Bit());

        act.Should().Throw<NotSupportedException>()
            .WithMessage("*CKKS*");
    }

    [Fact]
    public void ExportKeyBundle_produces_non_empty_keys()
    {
        using var km = new SealKeyManager();
        km.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());

        using var bundle = km.ExportKeyBundle();

        bundle.PublicKey.Should().NotBeEmpty();
        bundle.SecretKey.Should().NotBeEmpty();
        bundle.RelinKeys.Should().NotBeEmpty();
    }

    [Fact]
    public void Dispose_clears_keys()
    {
        var km = new SealKeyManager();
        km.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());

        km.Dispose();

        km.IsInitialized.Should().BeFalse();
        km.Context.Should().BeNull();
        km.PublicKey.Should().BeNull();
        km.SecretKey.Should().BeNull();
    }
}
