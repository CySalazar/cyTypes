using System.Text;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class AesSivEngineTests : IDisposable
{
    private readonly AesSivEngine _engine;

    public AesSivEngineTests()
    {
        _engine = AesSivEngine.CreateWithRandomKey();
    }

    [Fact]
    public void EncryptDeterministic_DecryptDeterministic_roundtrip()
    {
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        var ciphertext = _engine.EncryptDeterministic(plaintext);
        var decrypted = _engine.DecryptDeterministic(ciphertext);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void EncryptDeterministic_same_input_produces_same_output()
    {
        var plaintext = Encoding.UTF8.GetBytes("deterministic test");

        var ct1 = _engine.EncryptDeterministic(plaintext);
        var ct2 = _engine.EncryptDeterministic(plaintext);

        ct1.Should().Equal(ct2);
    }

    [Fact]
    public void EncryptDeterministic_different_inputs_produce_different_outputs()
    {
        var pt1 = Encoding.UTF8.GetBytes("hello");
        var pt2 = Encoding.UTF8.GetBytes("world");

        var ct1 = _engine.EncryptDeterministic(pt1);
        var ct2 = _engine.EncryptDeterministic(pt2);

        ct1.Should().NotEqual(ct2);
    }

    [Fact]
    public void CiphertextEquals_same_ciphertexts_returns_true()
    {
        var pt = Encoding.UTF8.GetBytes("test");
        var ct1 = _engine.EncryptDeterministic(pt);
        var ct2 = _engine.EncryptDeterministic(pt);

        _engine.CiphertextEquals(ct1, ct2).Should().BeTrue();
    }

    [Fact]
    public void CiphertextEquals_different_ciphertexts_returns_false()
    {
        var ct1 = _engine.EncryptDeterministic(Encoding.UTF8.GetBytes("a"));
        var ct2 = _engine.EncryptDeterministic(Encoding.UTF8.GetBytes("b"));

        _engine.CiphertextEquals(ct1, ct2).Should().BeFalse();
    }

    [Fact]
    public void EncryptDeterministic_empty_input()
    {
        var empty = Array.Empty<byte>();

        var ct = _engine.EncryptDeterministic(empty);
        var decrypted = _engine.DecryptDeterministic(ct);

        decrypted.Should().BeEmpty();
    }

    [Fact]
    public void Different_keys_produce_different_ciphertexts()
    {
        using var engine2 = AesSivEngine.CreateWithRandomKey();
        var pt = Encoding.UTF8.GetBytes("same plaintext");

        var ct1 = _engine.EncryptDeterministic(pt);
        var ct2 = engine2.EncryptDeterministic(pt);

        ct1.Should().NotEqual(ct2);
    }

    [Fact]
    public void Constructor_rejects_wrong_key_size()
    {
        var act = () => new AesSivEngine(new byte[16]);

        act.Should().Throw<ArgumentException>().WithMessage("*32*");
    }

    public void Dispose()
    {
        _engine.Dispose();
    }
}
