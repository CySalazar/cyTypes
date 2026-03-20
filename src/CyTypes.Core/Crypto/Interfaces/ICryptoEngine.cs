namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Defines symmetric authenticated encryption and decryption operations.
/// </summary>
public interface ICryptoEngine
{
    /// <summary>
    /// Encrypts the plaintext using the provided key and optional associated data.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="associatedData">Optional additional authenticated data.</param>
    /// <returns>The encrypted ciphertext including any authentication metadata.</returns>
    byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default);

    /// <summary>
    /// Decrypts the ciphertext using the provided key and optional associated data.
    /// </summary>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="associatedData">Optional additional authenticated data.</param>
    /// <returns>The decrypted plaintext.</returns>
    byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default);
}
