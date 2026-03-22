using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class SealComparisonEngineTests : IDisposable
{
    private readonly SealKeyManager _bfvKeyManager;
    private readonly SealBfvEngine _bfvEngine;
    private readonly SealKeyManager _ckksKeyManager;
    private readonly SealCkksEngine _ckksEngine;
    private readonly SealComparisonEngine _bfvComparison;
    private readonly SealComparisonEngine _ckksComparison;

    public SealComparisonEngineTests()
    {
        _bfvKeyManager = new SealKeyManager();
        _bfvKeyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _bfvEngine = new SealBfvEngine(_bfvKeyManager);
        _bfvComparison = new SealComparisonEngine(_bfvEngine);

        _ckksKeyManager = new SealKeyManager();
        _ckksKeyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
        _ckksEngine = new SealCkksEngine(_ckksKeyManager);
        _ckksComparison = new SealComparisonEngine(_ckksEngine);
    }

    [Fact]
    public void BFV_ComputeDifference_and_DecryptComparison_a_greater_than_b()
    {
        var a = _bfvEngine.Encrypt(100);
        var b = _bfvEngine.Encrypt(42);

        var diff = _bfvComparison.ComputeDifference(a, b);
        var result = _bfvComparison.DecryptComparison(diff);

        result.Should().Be(1);
    }

    [Fact]
    public void BFV_ComputeDifference_and_DecryptComparison_a_less_than_b()
    {
        var a = _bfvEngine.Encrypt(10);
        var b = _bfvEngine.Encrypt(50);

        var diff = _bfvComparison.ComputeDifference(a, b);
        var result = _bfvComparison.DecryptComparison(diff);

        result.Should().Be(-1);
    }

    [Fact]
    public void BFV_DecryptEquality_equal_values()
    {
        var a = _bfvEngine.Encrypt(42);
        var b = _bfvEngine.Encrypt(42);

        var diff = _bfvComparison.ComputeDifference(a, b);
        var equal = _bfvComparison.DecryptEquality(diff);

        equal.Should().BeTrue();
    }

    [Fact]
    public void BFV_DecryptEquality_different_values()
    {
        var a = _bfvEngine.Encrypt(42);
        var b = _bfvEngine.Encrypt(43);

        var diff = _bfvComparison.ComputeDifference(a, b);
        var equal = _bfvComparison.DecryptEquality(diff);

        equal.Should().BeFalse();
    }

    [Fact]
    public void CKKS_ComputeDifference_and_DecryptComparison_a_greater_than_b()
    {
        var a = _ckksEngine.Encrypt(100.5);
        var b = _ckksEngine.Encrypt(42.3);

        var diff = _ckksComparison.ComputeDifference(a, b);
        var result = _ckksComparison.DecryptComparison(diff);

        result.Should().Be(1);
    }

    [Fact]
    public void CKKS_DecryptEquality_with_epsilon()
    {
        var a = _ckksEngine.Encrypt(42.0);
        var b = _ckksEngine.Encrypt(42.0);

        var diff = _ckksComparison.ComputeDifference(a, b);
        var equal = _ckksComparison.DecryptEquality(diff, 1e-4);

        equal.Should().BeTrue();
    }

    public void Dispose()
    {
        _bfvEngine.Dispose();
        _bfvKeyManager.Dispose();
        _ckksEngine.Dispose();
        _ckksKeyManager.Dispose();
    }
}
