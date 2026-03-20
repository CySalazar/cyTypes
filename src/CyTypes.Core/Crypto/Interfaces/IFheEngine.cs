using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Defines fully homomorphic encryption operations over encrypted integers.
/// </summary>
public interface IFheEngine
{
    /// <summary>Gets the FHE scheme used by this engine.</summary>
    FheScheme Scheme { get; }

    /// <summary>Encrypts a plaintext integer value.</summary>
    byte[] Encrypt(long value);

    /// <summary>Decrypts an FHE ciphertext back to a plaintext integer.</summary>
    long Decrypt(byte[] ciphertext);

    /// <summary>Performs homomorphic addition on two ciphertexts.</summary>
    byte[] Add(byte[] a, byte[] b);

    /// <summary>Performs homomorphic subtraction on two ciphertexts.</summary>
    byte[] Subtract(byte[] a, byte[] b);

    /// <summary>Performs homomorphic multiplication on two ciphertexts.</summary>
    byte[] Multiply(byte[] a, byte[] b);

    /// <summary>Performs homomorphic negation on a ciphertext.</summary>
    byte[] Negate(byte[] a);

    /// <summary>Returns the remaining noise budget in bits for the given ciphertext.</summary>
    int GetNoiseBudget(byte[] ciphertext);
}
