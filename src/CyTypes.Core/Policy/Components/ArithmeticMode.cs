namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Specifies the arithmetic computation mode for encrypted numeric operations.
/// </summary>
public enum ArithmeticMode
{
    /// <summary>Full homomorphic encryption allowing arbitrary arithmetic on ciphertext.</summary>
    HomomorphicFull,

    /// <summary>Basic homomorphic encryption supporting addition and limited multiplication.</summary>
    HomomorphicBasic,

    /// <summary>Performs arithmetic inside a secure enclave after decryption.</summary>
    SecureEnclave
}
