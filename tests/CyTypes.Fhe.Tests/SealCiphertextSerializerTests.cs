using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class SealCiphertextSerializerTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealBfvEngine _engine;

    public SealCiphertextSerializerTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _engine = new SealBfvEngine(_keyManager);
    }

    [Fact]
    public void Serialized_ciphertext_has_FHE_magic_header()
    {
        var ct = _engine.Encrypt(42);

        ct[0].Should().Be(0xFE);
        ct[1].Should().Be(SealCiphertextSerializer.SchemeBfv);
    }

    [Fact]
    public void IsFheCiphertext_returns_true_for_FHE_data()
    {
        var ct = _engine.Encrypt(42);

        SealCiphertextSerializer.IsFheCiphertext(ct).Should().BeTrue();
    }

    [Fact]
    public void IsFheCiphertext_returns_false_for_AES_data()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        SealCiphertextSerializer.IsFheCiphertext(data).Should().BeFalse();
    }

    [Fact]
    public void GetSchemeMarker_returns_BFV_for_BFV_ciphertext()
    {
        var ct = _engine.Encrypt(42);

        SealCiphertextSerializer.GetSchemeMarker(ct).Should().Be(SealCiphertextSerializer.SchemeBfv);
    }

    [Fact]
    public void Serialize_Deserialize_roundtrip()
    {
        var ct = _engine.Encrypt(42);
        // The engine internally uses the serializer, so decrypt verifies the round-trip
        var result = _engine.Decrypt(ct);

        result.Should().Be(42);
    }

    public void Dispose()
    {
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
