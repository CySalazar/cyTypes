using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Operations;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Operations;

public sealed class SecureEnclaveExecutorTests
{
    private readonly ICryptoEngine _engine = new AesGcmEngine();
    private readonly byte[] _key;
    private readonly SecureEnclaveExecutor _executor;

    public SecureEnclaveExecutorTests()
    {
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
        _executor = new SecureEnclaveExecutor(_engine);
    }

    private byte[] EncryptInt(int value) => _engine.Encrypt(BitConverter.GetBytes(value), _key);
    private int DecryptInt(byte[] ciphertext) => BitConverter.ToInt32(_engine.Decrypt(ciphertext, _key));

    [Fact]
    public void Add_int_encrypts_5_and_3_result_is_8()
    {
        var encA = EncryptInt(5);
        var encB = EncryptInt(3);

        var result = _executor.Add<int>(encA, encB, _key);

        DecryptInt(result).Should().Be(8);
    }

    [Fact]
    public void Subtract_int_10_minus_3_is_7()
    {
        var encA = EncryptInt(10);
        var encB = EncryptInt(3);

        var result = _executor.Subtract<int>(encA, encB, _key);

        DecryptInt(result).Should().Be(7);
    }

    [Fact]
    public void Multiply_int_4_times_6_is_24()
    {
        var encA = EncryptInt(4);
        var encB = EncryptInt(6);

        var result = _executor.Multiply<int>(encA, encB, _key);

        DecryptInt(result).Should().Be(24);
    }

    [Fact]
    public void Compare_int_equal_values_return_true()
    {
        var encA = EncryptInt(42);
        var encB = EncryptInt(42);

        var result = _executor.Compare<int>(encA, encB, _key);

        result.Should().BeTrue();
    }

    [Fact]
    public void Compare_int_different_values_return_false()
    {
        var encA = EncryptInt(42);
        var encB = EncryptInt(99);

        var result = _executor.Compare<int>(encA, encB, _key);

        result.Should().BeFalse();
    }
}
