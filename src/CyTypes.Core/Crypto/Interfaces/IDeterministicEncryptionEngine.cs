namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Provides deterministic encryption for equality-preserving operations.
/// Same plaintext + same key always produces the same ciphertext, enabling
/// encrypted equality checks without decryption (AES-SIV / RFC 5297).
/// </summary>
/// <remarks>
/// SECURITY: Deterministic encryption leaks equality patterns — two identical
/// plaintexts produce identical ciphertexts. This is by design for equality checks
/// but weaker than randomized encryption (IND-CPA, not IND-CCA2).
/// </remarks>
public interface IDeterministicEncryptionEngine
{
    /// <summary>Encrypts plaintext deterministically. Same input always produces same output.</summary>
    byte[] EncryptDeterministic(byte[] plaintext);

    /// <summary>Decrypts a deterministically encrypted ciphertext.</summary>
    byte[] DecryptDeterministic(byte[] ciphertext);

    /// <summary>
    /// Compares two deterministic ciphertexts for equality using constant-time comparison.
    /// No decryption is performed.
    /// </summary>
    bool CiphertextEquals(byte[] a, byte[] b);
}
