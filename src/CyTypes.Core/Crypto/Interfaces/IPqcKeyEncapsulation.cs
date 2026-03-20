namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Defines post-quantum key encapsulation mechanism (KEM) operations.
/// </summary>
public interface IPqcKeyEncapsulation
{
    /// <summary>Encapsulates a shared secret using the given public key.</summary>
    /// <returns>A tuple of (ciphertext, sharedSecret).</returns>
    (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey);

    /// <summary>Decapsulates the shared secret from the ciphertext using the secret key.</summary>
    byte[] Decapsulate(byte[] ciphertext, byte[] secretKey);

    /// <summary>Generates a new key pair for encapsulation.</summary>
    /// <returns>A tuple of (publicKey, secretKey).</returns>
    (byte[] publicKey, byte[] secretKey) GenerateKeyPair();
}
