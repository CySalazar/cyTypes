using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Integration;

[Collection("FHE")]
public sealed class CkksIntegrationTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealCkksEngine _engine;
    private readonly SecurityPolicy _policy;

    public CkksIntegrationTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
        _engine = new SealCkksEngine(_keyManager);
        FheEngineProvider.Configure(_engine);

        _policy = SecurityPolicy.HomomorphicBasic;
    }

    [Fact]
    public void CyDouble_add_via_CKKS()
    {
        var a = new CyDouble(10.5, _policy);
        var b = new CyDouble(20.3, _policy);

        var result = a + b;

        result.ToInsecureDouble().Should().BeApproximately(30.8, 1e-3);
    }

    [Fact]
    public void CyDouble_subtract_via_CKKS()
    {
        var a = new CyDouble(50.0, _policy);
        var b = new CyDouble(17.5, _policy);

        var result = a - b;

        result.ToInsecureDouble().Should().BeApproximately(32.5, 1e-3);
    }

    [Fact]
    public void CyDouble_multiply_via_CKKS()
    {
        var a = new CyDouble(3.0, _policy);
        var b = new CyDouble(7.0, _policy);

        var result = a * b;

        result.ToInsecureDouble().Should().BeApproximately(21.0, 0.1);
    }

    [Fact]
    public void CyFloat_add_via_CKKS()
    {
        var a = new CyFloat(5.5f, _policy);
        var b = new CyFloat(2.3f, _policy);

        var result = a + b;

        result.ToInsecureFloat().Should().BeApproximately(7.8f, 0.01f);
    }

    [Fact]
    public void CyFloat_multiply_via_CKKS()
    {
        var a = new CyFloat(4.0f, _policy);
        var b = new CyFloat(3.0f, _policy);

        var result = a * b;

        result.ToInsecureFloat().Should().BeApproximately(12.0f, 0.1f);
    }

    [Fact]
    public void CyDecimal_add_via_CKKS()
    {
        var a = new CyDecimal(100.50m, _policy);
        var b = new CyDecimal(200.25m, _policy);

        var result = a + b;

        // CKKS is approximate; decimal precision is NOT preserved
        ((double)result.ToInsecureDecimal()).Should().BeApproximately(300.75, 0.01);
    }

    [Fact]
    public void CyDouble_division_falls_back_to_SecureEnclave()
    {
        // Division uses FheOp.None — should fall through to decrypt path
        var a = new CyDouble(10.0, _policy);
        var b = new CyDouble(2.0, _policy);

        var result = a / b;

        result.ToInsecureDouble().Should().BeApproximately(5.0, 1e-6);
    }

    [Fact]
    public void CyDouble_policy_is_preserved_through_FHE_operations()
    {
        var a = new CyDouble(1.0, _policy);
        var b = new CyDouble(2.0, _policy);

        var result = a + b;

        result.Policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicBasic);
    }

    [Fact]
    public void CyDouble_SupportsFhe_returns_true_with_HomomorphicBasic()
    {
        var d = new CyDouble(42.0, _policy);
        d.SupportsFhe.Should().BeTrue();
    }

    [Fact]
    public void CyDouble_SupportsFhe_returns_false_with_default_policy()
    {
        var d = new CyDouble(42.0);
        d.SupportsFhe.Should().BeFalse();
    }

    public void Dispose()
    {
        FheEngineProvider.Reset();
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
