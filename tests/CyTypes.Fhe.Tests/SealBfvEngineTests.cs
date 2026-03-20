using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class SealBfvEngineTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealBfvEngine _engine;

    public SealBfvEngineTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _engine = new SealBfvEngine(_keyManager);
    }

    [Fact]
    public void Encrypt_Decrypt_roundtrip()
    {
        var ciphertext = _engine.Encrypt(42);
        var result = _engine.Decrypt(ciphertext);

        result.Should().Be(42);
    }

    [Fact]
    public void Encrypt_Decrypt_negative_value()
    {
        var ciphertext = _engine.Encrypt(-100);
        var result = _engine.Decrypt(ciphertext);

        result.Should().Be(-100);
    }

    [Fact]
    public void Add_produces_correct_result()
    {
        var a = _engine.Encrypt(10);
        var b = _engine.Encrypt(20);

        var result = _engine.Add(a, b);

        _engine.Decrypt(result).Should().Be(30);
    }

    [Fact]
    public void Subtract_produces_correct_result()
    {
        var a = _engine.Encrypt(50);
        var b = _engine.Encrypt(20);

        var result = _engine.Subtract(a, b);

        _engine.Decrypt(result).Should().Be(30);
    }

    [Fact]
    public void Multiply_produces_correct_result()
    {
        var a = _engine.Encrypt(7);
        var b = _engine.Encrypt(6);

        var result = _engine.Multiply(a, b);

        _engine.Decrypt(result).Should().Be(42);
    }

    [Fact]
    public void Negate_produces_correct_result()
    {
        var a = _engine.Encrypt(42);

        var result = _engine.Negate(a);

        _engine.Decrypt(result).Should().Be(-42);
    }

    [Fact]
    public void GetNoiseBudget_returns_positive_for_fresh_ciphertext()
    {
        var ciphertext = _engine.Encrypt(10);
        var budget = _engine.GetNoiseBudget(ciphertext);

        budget.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Multiply_reduces_noise_budget()
    {
        var a = _engine.Encrypt(3);
        var b = _engine.Encrypt(4);

        var initialBudget = _engine.GetNoiseBudget(a);
        var product = _engine.Multiply(a, b);
        var afterMultiply = _engine.GetNoiseBudget(product);

        afterMultiply.Should().BeLessThan(initialBudget);
    }

    [Fact]
    public void Scheme_returns_BFV()
    {
        _engine.Scheme.Should().Be(FheScheme.BFV);
    }

    [Fact]
    public void Chained_additions_produce_correct_result()
    {
        var a = _engine.Encrypt(1);
        var b = _engine.Encrypt(2);
        var c = _engine.Encrypt(3);

        var sum = _engine.Add(_engine.Add(a, b), c);

        _engine.Decrypt(sum).Should().Be(6);
    }

    public void Dispose()
    {
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
