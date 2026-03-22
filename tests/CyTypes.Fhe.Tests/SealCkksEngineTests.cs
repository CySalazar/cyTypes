using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class SealCkksEngineTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealCkksEngine _engine;

    public SealCkksEngineTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
        _engine = new SealCkksEngine(_keyManager);
    }

    [Fact]
    public void Scheme_returns_CKKS()
    {
        _engine.Scheme.Should().Be(FheScheme.CKKS);
    }

    [Fact]
    public void Scale_returns_default_scale()
    {
        _engine.Scale.Should().Be(SealParameterPresets.DefaultCkksScale);
    }

    [Fact]
    public void Encrypt_Decrypt_roundtrip_preserves_value()
    {
        var ct = _engine.Encrypt(3.14159);
        var result = _engine.Decrypt(ct);

        result.Should().BeApproximately(3.14159, 1e-4);
    }

    [Fact]
    public void Encrypt_Decrypt_negative_value()
    {
        var ct = _engine.Encrypt(-42.5);
        var result = _engine.Decrypt(ct);

        result.Should().BeApproximately(-42.5, 1e-4);
    }

    [Fact]
    public void Encrypt_Decrypt_zero()
    {
        var ct = _engine.Encrypt(0.0);
        var result = _engine.Decrypt(ct);

        result.Should().BeApproximately(0.0, 1e-4);
    }

    [Fact]
    public void Add_produces_correct_sum()
    {
        var a = _engine.Encrypt(10.5);
        var b = _engine.Encrypt(20.3);

        var sum = _engine.Add(a, b);
        var result = _engine.Decrypt(sum);

        result.Should().BeApproximately(30.8, 1e-4);
    }

    [Fact]
    public void Subtract_produces_correct_difference()
    {
        var a = _engine.Encrypt(50.0);
        var b = _engine.Encrypt(17.5);

        var diff = _engine.Subtract(a, b);
        var result = _engine.Decrypt(diff);

        result.Should().BeApproximately(32.5, 1e-4);
    }

    [Fact]
    public void Multiply_produces_correct_product()
    {
        var a = _engine.Encrypt(3.0);
        var b = _engine.Encrypt(7.0);

        var product = _engine.Multiply(a, b);
        var result = _engine.Decrypt(product);

        result.Should().BeApproximately(21.0, 1e-2);
    }

    [Fact]
    public void Negate_produces_correct_negation()
    {
        var ct = _engine.Encrypt(42.0);

        var negated = _engine.Negate(ct);
        var result = _engine.Decrypt(negated);

        result.Should().BeApproximately(-42.0, 1e-4);
    }

    [Fact]
    public void Chained_operations_add_add()
    {
        var a = _engine.Encrypt(1.0);
        var b = _engine.Encrypt(2.0);
        var c = _engine.Encrypt(3.0);

        var ab = _engine.Add(a, b);
        var abc = _engine.Add(ab, c);
        var result = _engine.Decrypt(abc);

        result.Should().BeApproximately(6.0, 1e-4);
    }

    [Fact]
    public void GetNoiseBudget_returns_positive_chain_index()
    {
        var ct = _engine.Encrypt(42.0);
        var budget = _engine.GetNoiseBudget(ct);

        budget.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Rescale_reduces_chain_index()
    {
        var a = _engine.Encrypt(3.0);
        var b = _engine.Encrypt(7.0);
        var product = _engine.Multiply(a, b);

        var levelAfterMul = _engine.GetNoiseBudget(product);
        var levelFresh = _engine.GetNoiseBudget(a);

        levelAfterMul.Should().BeLessThan(levelFresh);
    }

    public void Dispose()
    {
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
