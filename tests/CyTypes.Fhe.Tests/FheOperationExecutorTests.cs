using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Fhe.NoiseBudget;
using CyTypes.Fhe.Operations;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class FheOperationExecutorTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealBfvEngine _engine;
    private readonly FheOperationExecutor _executor;

    public FheOperationExecutorTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _engine = new SealBfvEngine(_keyManager);
        _executor = new FheOperationExecutor(_engine);
    }

    [Fact]
    public void Add_end_to_end()
    {
        var a = _engine.Encrypt(15);
        var b = _engine.Encrypt(27);

        var result = _executor.Add(a, b);

        _engine.Decrypt(result).Should().Be(42);
    }

    [Fact]
    public void Subtract_end_to_end()
    {
        var a = _engine.Encrypt(100);
        var b = _engine.Encrypt(58);

        var result = _executor.Subtract(a, b);

        _engine.Decrypt(result).Should().Be(42);
    }

    [Fact]
    public void Multiply_end_to_end()
    {
        var a = _engine.Encrypt(6);
        var b = _engine.Encrypt(7);

        var result = _executor.Multiply(a, b);

        _engine.Decrypt(result).Should().Be(42);
    }

    [Fact]
    public void Negate_end_to_end()
    {
        var a = _engine.Encrypt(42);

        var result = _executor.Negate(a);

        _engine.Decrypt(result).Should().Be(-42);
    }

    [Fact]
    public void Divide_throws_NotSupportedException()
    {
        var a = _engine.Encrypt(10);
        var b = _engine.Encrypt(2);

        var act = () => _executor.Divide(a, b);

        act.Should().Throw<NotSupportedException>()
            .WithMessage("*SecureEnclave*");
    }

    [Fact]
    public void Modulo_throws_NotSupportedException()
    {
        var a = _engine.Encrypt(10);
        var b = _engine.Encrypt(3);

        var act = () => _executor.Modulo(a, b);

        act.Should().Throw<NotSupportedException>()
            .WithMessage("*SecureEnclave*");
    }

    public void Dispose()
    {
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
