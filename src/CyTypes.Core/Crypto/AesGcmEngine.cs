using System.Security.Cryptography;
using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Core.Crypto;

/// <summary>
/// AES-256-GCM authenticated encryption engine. Output layout: [nonce:12][ciphertext:N][tag:16].
/// </summary>
public sealed class AesGcmEngine : ICryptoEngine
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    /// <summary>
    /// Encrypts the plaintext using AES-GCM with a random nonce.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">The 256-bit encryption key.</param>
    /// <param name="associatedData">Optional additional authenticated data.</param>
    /// <returns>The combined nonce, ciphertext, and authentication tag.</returns>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        // Layout: [nonce:12][ciphertext:N][tag:16]
        var outputLength = NonceSize + plaintext.Length + TagSize;
        var output = new byte[outputLength];

        var nonce = output.AsSpan(0, NonceSize);
        var ciphertext = output.AsSpan(NonceSize, plaintext.Length);
        var tag = output.AsSpan(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return output;
    }

    /// <summary>
    /// Decrypts AES-GCM ciphertext and verifies the authentication tag.
    /// </summary>
    /// <param name="ciphertext">The combined nonce, ciphertext, and tag.</param>
    /// <param name="key">The 256-bit encryption key.</param>
    /// <param name="associatedData">Optional additional authenticated data.</param>
    /// <returns>The decrypted plaintext.</returns>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < NonceSize + TagSize)
            throw new CryptographicException("Ciphertext is too short.");

        var nonce = ciphertext[..NonceSize];
        var encryptedLength = ciphertext.Length - NonceSize - TagSize;
        var encrypted = ciphertext.Slice(NonceSize, encryptedLength);
        var tag = ciphertext[^TagSize..];

        var plaintext = new byte[encryptedLength];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, encrypted, tag, plaintext, associatedData);

        return plaintext;
    }
}
