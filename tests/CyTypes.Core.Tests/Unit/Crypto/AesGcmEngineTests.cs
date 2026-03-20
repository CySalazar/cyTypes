using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class AesGcmEngineTests
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly ICryptoEngine _engine = new AesGcmEngine();

    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void Encrypt_then_Decrypt_returns_original_plaintext()
    {
        var key = GenerateKey();
        var plaintext = "Hello, AES-GCM!"u8.ToArray();

        var ciphertext = _engine.Encrypt(plaintext, key);
        var decrypted = _engine.Decrypt(ciphertext, key);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void Different_plaintexts_produce_different_ciphertexts()
    {
        var key = GenerateKey();
        var plaintext1 = "Message one"u8.ToArray();
        var plaintext2 = "Message two"u8.ToArray();

        var ciphertext1 = _engine.Encrypt(plaintext1, key);
        var ciphertext2 = _engine.Encrypt(plaintext2, key);

        ciphertext1.Should().NotEqual(ciphertext2);
    }

    [Fact]
    public void Tampered_ciphertext_fails_decryption()
    {
        var key = GenerateKey();
        var plaintext = "Tamper test"u8.ToArray();

        var ciphertext = _engine.Encrypt(plaintext, key);

        // Flip a byte in the middle of the encrypted portion
        var midpoint = NonceSize + (ciphertext.Length - NonceSize - TagSize) / 2;
        ciphertext[midpoint] ^= 0xFF;

        var act = () => _engine.Decrypt(ciphertext, key);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Tampered_tag_fails_decryption()
    {
        var key = GenerateKey();
        var plaintext = "Tag tamper test"u8.ToArray();

        var ciphertext = _engine.Encrypt(plaintext, key);

        // Flip the last byte (part of the tag)
        ciphertext[^1] ^= 0xFF;

        var act = () => _engine.Decrypt(ciphertext, key);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Each_encrypt_call_produces_unique_nonces()
    {
        var key = GenerateKey();
        var plaintext = "Same plaintext"u8.ToArray();

        var ciphertext1 = _engine.Encrypt(plaintext, key);
        var ciphertext2 = _engine.Encrypt(plaintext, key);

        // The nonces (first 12 bytes) should differ
        ciphertext1.AsSpan(0, NonceSize).ToArray()
            .Should().NotEqual(ciphertext2.AsSpan(0, NonceSize).ToArray());

        // Full ciphertexts should also differ
        ciphertext1.Should().NotEqual(ciphertext2);
    }

    [Fact]
    public void Ciphertext_length_equals_plaintext_plus_nonce_plus_tag()
    {
        var key = GenerateKey();
        var plaintext = "Length check"u8.ToArray();

        var ciphertext = _engine.Encrypt(plaintext, key);

        ciphertext.Should().HaveCount(plaintext.Length + NonceSize + TagSize);
    }

    [Fact]
    public void Decrypt_with_wrong_key_throws_CryptographicException()
    {
        var key = GenerateKey();
        var wrongKey = GenerateKey();
        var plaintext = "Wrong key test"u8.ToArray();

        var ciphertext = _engine.Encrypt(plaintext, key);

        var act = () => _engine.Decrypt(ciphertext, wrongKey);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_of_too_short_ciphertext_throws_CryptographicException()
    {
        var key = GenerateKey();
        var tooShort = new byte[NonceSize + TagSize - 1];

        var act = () => _engine.Decrypt(tooShort, key);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Encrypt_with_AAD_then_Decrypt_with_same_AAD_succeeds()
    {
        var key = GenerateKey();
        var plaintext = "AAD roundtrip"u8.ToArray();
        var aad = "context-data"u8.ToArray();

        var ciphertext = _engine.Encrypt(plaintext, key, aad);
        var decrypted = _engine.Decrypt(ciphertext, key, aad);

        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void Decrypt_with_wrong_AAD_fails()
    {
        var key = GenerateKey();
        var plaintext = "AAD mismatch"u8.ToArray();
        var aad = "correct-aad"u8.ToArray();
        var wrongAad = "wrong-aad"u8.ToArray();

        var ciphertext = _engine.Encrypt(plaintext, key, aad);

        var act = () => _engine.Decrypt(ciphertext, key, wrongAad);
        act.Should().Throw<CryptographicException>();
    }
}
