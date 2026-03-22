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
/// Tests the "drop-in replacement" FHE path: users create CyInt/CyDouble/etc. with a
/// homomorphic policy and a plain value — the engine encrypts via BFV/CKKS automatically.
/// No direct SealBfvEngine.Encrypt() calls — the user never touches the engine.
/// </summary>
[Collection("FHE")]
public sealed class FheDropInReplacementTests : IDisposable
{
    private readonly SealKeyManager _bfvKeyManager;
    private readonly SealBfvEngine _bfvEngine;
    private readonly SealKeyManager _ckksKeyManager;
    private readonly SealCkksEngine _ckksEngine;

    public FheDropInReplacementTests()
    {
        _bfvKeyManager = new SealKeyManager();
        _bfvKeyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _bfvEngine = new SealBfvEngine(_bfvKeyManager);
        FheEngineProvider.Configure(_bfvEngine);

        _ckksKeyManager = new SealKeyManager();
        _ckksKeyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
        _ckksEngine = new SealCkksEngine(_ckksKeyManager);
        FheEngineProvider.Configure(_ckksEngine);
    }

    // ── CyInt (BFV) drop-in ────────────────────────────────

    [Fact]
    public void CyInt_drop_in_add_with_HomomorphicBasic()
    {
        using var a = new CyInt(42, SecurityPolicy.HomomorphicBasic);
        using var b = new CyInt(17, SecurityPolicy.HomomorphicBasic);

        using var result = a + b;

        result.ToInsecureInt().Should().Be(59);
        result.SupportsFhe.Should().BeTrue();
    }

    [Fact]
    public void CyInt_drop_in_subtract_with_HomomorphicBasic()
    {
        using var a = new CyInt(100, SecurityPolicy.HomomorphicBasic);
        using var b = new CyInt(37, SecurityPolicy.HomomorphicBasic);

        using var result = a - b;

        result.ToInsecureInt().Should().Be(63);
    }

    [Fact]
    public void CyInt_drop_in_multiply_with_HomomorphicBasic()
    {
        using var a = new CyInt(6, SecurityPolicy.HomomorphicBasic);
        using var b = new CyInt(7, SecurityPolicy.HomomorphicBasic);

        using var result = a * b;

        result.ToInsecureInt().Should().Be(42);
    }

    [Fact]
    public void CyInt_drop_in_chained_operations()
    {
        using var a = new CyInt(10, SecurityPolicy.HomomorphicBasic);
        using var b = new CyInt(20, SecurityPolicy.HomomorphicBasic);
        using var c = new CyInt(3, SecurityPolicy.HomomorphicBasic);

        using var sum = a + b;      // 30
        using var result = sum * c; // 90

        result.ToInsecureInt().Should().Be(90);
    }

    [Fact]
    public void CyInt_drop_in_negate_with_HomomorphicBasic()
    {
        using var a = new CyInt(42, SecurityPolicy.HomomorphicBasic);

        using var result = -a;

        result.ToInsecureInt().Should().Be(-42);
    }

    [Fact]
    public void CyInt_drop_in_preserves_policy()
    {
        using var a = new CyInt(1, SecurityPolicy.HomomorphicBasic);
        using var b = new CyInt(2, SecurityPolicy.HomomorphicBasic);

        using var result = a + b;

        result.Policy.Name.Should().Be("HomomorphicBasic");
        result.Policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicBasic);
    }

    // ── CyDouble (CKKS) drop-in ───────────────────────────

    [Fact]
    public void CyDouble_drop_in_add_with_HomomorphicBasic()
    {
        using var a = new CyDouble(10.5, SecurityPolicy.HomomorphicBasic);
        using var b = new CyDouble(20.3, SecurityPolicy.HomomorphicBasic);

        using var result = a + b;

        result.ToInsecureDouble().Should().BeApproximately(30.8, 1e-3);
        result.SupportsFhe.Should().BeTrue();
    }

    [Fact]
    public void CyDouble_drop_in_subtract_with_HomomorphicBasic()
    {
        using var a = new CyDouble(50.0, SecurityPolicy.HomomorphicBasic);
        using var b = new CyDouble(17.5, SecurityPolicy.HomomorphicBasic);

        using var result = a - b;

        result.ToInsecureDouble().Should().BeApproximately(32.5, 1e-3);
    }

    [Fact]
    public void CyDouble_drop_in_multiply_with_HomomorphicBasic()
    {
        using var a = new CyDouble(3.0, SecurityPolicy.HomomorphicBasic);
        using var b = new CyDouble(7.0, SecurityPolicy.HomomorphicBasic);

        using var result = a * b;

        result.ToInsecureDouble().Should().BeApproximately(21.0, 0.1);
    }

    [Fact]
    public void CyDouble_drop_in_chained_operations()
    {
        using var a = new CyDouble(2.5, SecurityPolicy.HomomorphicBasic);
        using var b = new CyDouble(4.0, SecurityPolicy.HomomorphicBasic);
        using var c = new CyDouble(3.0, SecurityPolicy.HomomorphicBasic);

        using var sum = a + b;      // 6.5
        using var result = sum * c; // 19.5

        result.ToInsecureDouble().Should().BeApproximately(19.5, 0.1);
    }

    [Fact]
    public void CyDouble_drop_in_preserves_policy()
    {
        using var a = new CyDouble(1.0, SecurityPolicy.HomomorphicBasic);
        using var b = new CyDouble(2.0, SecurityPolicy.HomomorphicBasic);

        using var result = a + b;

        result.Policy.Name.Should().Be("HomomorphicBasic");
        result.Policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicBasic);
    }

    // ── CyFloat (CKKS) drop-in ────────────────────────────

    [Fact]
    public void CyFloat_drop_in_add_with_HomomorphicBasic()
    {
        using var a = new CyFloat(5.5f, SecurityPolicy.HomomorphicBasic);
        using var b = new CyFloat(2.3f, SecurityPolicy.HomomorphicBasic);

        using var result = a + b;

        result.ToInsecureFloat().Should().BeApproximately(7.8f, 0.01f);
    }

    // ── CyDecimal (CKKS) drop-in ──────────────────────────

    [Fact]
    public void CyDecimal_drop_in_add_with_HomomorphicBasic()
    {
        using var a = new CyDecimal(100.50m, SecurityPolicy.HomomorphicBasic);
        using var b = new CyDecimal(200.25m, SecurityPolicy.HomomorphicBasic);

        using var result = a + b;

        // CKKS is approximate; decimal precision is NOT preserved
        ((double)result.ToInsecureDecimal()).Should().BeApproximately(300.75, 0.01);
    }

    // ── HomomorphicFull preset ─────────────────────────────

    [Fact]
    public void CyInt_drop_in_with_HomomorphicFull_policy()
    {
        using var a = new CyInt(10, SecurityPolicy.HomomorphicFull);
        using var b = new CyInt(20, SecurityPolicy.HomomorphicFull);

        using var result = a + b;

        result.ToInsecureInt().Should().Be(30);
        result.Policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicFull);
    }

    [Fact]
    public void CyDouble_drop_in_with_HomomorphicFull_policy()
    {
        using var a = new CyDouble(3.14, SecurityPolicy.HomomorphicFull);
        using var b = new CyDouble(2.72, SecurityPolicy.HomomorphicFull);

        using var result = a + b;

        result.ToInsecureDouble().Should().BeApproximately(5.86, 1e-2);
        result.Policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicFull);
    }

    public void Dispose()
    {
        FheEngineProvider.Reset();
        _ckksEngine.Dispose();
        _ckksKeyManager.Dispose();
        _bfvEngine.Dispose();
        _bfvKeyManager.Dispose();
    }
}
