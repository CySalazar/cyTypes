using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Integration;

/// <summary>
/// End-to-end tests verifying that CyInt/CyLong operators route through the FHE engine
/// when configured with a HomomorphicBasic policy and a real SealBfvEngine.
/// </summary>
public sealed class FheIntegrationTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealBfvEngine _engine;
    private readonly SecurityPolicy _policy;

    public FheIntegrationTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _engine = new SealBfvEngine(_keyManager);
        FheEngineProvider.Configure(_engine);

        _policy = new SecurityPolicyBuilder()
            .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
            .Build();
    }

    [Fact]
    public void CyInt_Add_operates_on_ciphertexts_without_decryption()
    {
        var a = new CyInt(42, _policy);
        var b = new CyInt(17, _policy);

        var result = a + b;

        result.SupportsFhe.Should().BeTrue();
        result.DecryptValue().Should().Be(59);
    }

    [Fact]
    public void CyInt_Subtract_operates_on_ciphertexts_without_decryption()
    {
        var a = new CyInt(100, _policy);
        var b = new CyInt(58, _policy);

        var result = a - b;

        result.DecryptValue().Should().Be(42);
    }

    [Fact]
    public void CyInt_Multiply_operates_on_ciphertexts_without_decryption()
    {
        var a = new CyInt(6, _policy);
        var b = new CyInt(7, _policy);

        var result = a * b;

        result.DecryptValue().Should().Be(42);
    }

    [Fact]
    public void CyLong_Add_operates_on_ciphertexts_without_decryption()
    {
        var a = new CyLong(100_000L, _policy);
        var b = new CyLong(200_000L, _policy);

        var result = a + b;

        result.SupportsFhe.Should().BeTrue();
        result.DecryptValue().Should().Be(300_000L);
    }

    [Fact]
    public void CyInt_chained_operations_remain_homomorphic()
    {
        var a = new CyInt(10, _policy);
        var b = new CyInt(20, _policy);
        var c = new CyInt(3, _policy);

        var result = (a + b) * c;

        result.DecryptValue().Should().Be(90);
    }

    public void Dispose()
    {
        FheEngineProvider.Reset();
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
