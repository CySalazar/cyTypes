using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Defines fully homomorphic encryption operations over encrypted floating-point values
/// using the CKKS (Cheon-Kim-Kim-Song) scheme for approximate arithmetic.
/// </summary>
public interface IFheFloatingPointEngine
{
    /// <summary>Gets the FHE scheme used by this engine.</summary>
    FheScheme Scheme { get; }

    /// <summary>Gets the scale used for CKKS encoding.</summary>
    double Scale { get; }

    /// <summary>Encrypts a plaintext floating-point value.</summary>
    byte[] Encrypt(double value);

    /// <summary>Decrypts an FHE ciphertext back to a plaintext floating-point value.</summary>
    double Decrypt(byte[] ciphertext);

    /// <summary>Performs homomorphic addition on two ciphertexts.</summary>
    byte[] Add(byte[] a, byte[] b);

    /// <summary>Performs homomorphic subtraction on two ciphertexts.</summary>
    byte[] Subtract(byte[] a, byte[] b);

    /// <summary>Performs homomorphic multiplication on two ciphertexts (includes automatic rescaling).</summary>
    byte[] Multiply(byte[] a, byte[] b);

    /// <summary>Performs homomorphic negation on a ciphertext.</summary>
    byte[] Negate(byte[] a);

    /// <summary>Manually rescales a ciphertext to reduce the scale after multiplication.</summary>
    byte[] Rescale(byte[] ciphertext);

    /// <summary>Returns the number of remaining modulus-switching levels for the given ciphertext.</summary>
    int GetNoiseBudget(byte[] ciphertext);
}
