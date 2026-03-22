using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Fhe.Operations;

/// <summary>
/// Executes CKKS FHE arithmetic operations (add, subtract, multiply, negate)
/// by delegating to an <see cref="IFheFloatingPointEngine"/>.
/// Handles automatic rescaling after multiplication.
/// </summary>
public sealed class CkksOperationExecutor
{
    private readonly IFheFloatingPointEngine _engine;

    /// <summary>Initializes a new executor with the specified CKKS FHE engine.</summary>
    public CkksOperationExecutor(IFheFloatingPointEngine engine)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
    }

    /// <summary>Performs homomorphic addition on two ciphertexts.</summary>
    public byte[] Add(byte[] a, byte[] b) => _engine.Add(a, b);

    /// <summary>Performs homomorphic subtraction on two ciphertexts.</summary>
    public byte[] Subtract(byte[] a, byte[] b) => _engine.Subtract(a, b);

    /// <summary>Performs homomorphic multiplication with automatic rescaling.</summary>
    public byte[] Multiply(byte[] a, byte[] b) => _engine.Multiply(a, b);

    /// <summary>Performs homomorphic negation on a ciphertext.</summary>
    public byte[] Negate(byte[] a) => _engine.Negate(a);

    /// <summary>Manually rescales a ciphertext.</summary>
    public byte[] Rescale(byte[] ciphertext) => _engine.Rescale(ciphertext);

    /// <summary>Returns the remaining level count for the ciphertext.</summary>
    public int GetRemainingLevels(byte[] ciphertext) => _engine.GetNoiseBudget(ciphertext);

    /// <summary>
    /// Division is not supported in CKKS FHE. Use SecureEnclave mode instead.
    /// </summary>
    public byte[] Divide(byte[] a, byte[] b) =>
        throw new NotSupportedException(
            "CKKS FHE does not support division. Use ArithmeticMode.SecureEnclave for division operations.");

    /// <summary>
    /// Modulo is not supported in CKKS FHE. Use SecureEnclave mode instead.
    /// </summary>
    public byte[] Modulo(byte[] a, byte[] b) =>
        throw new NotSupportedException(
            "CKKS FHE does not support modulo operations. Use ArithmeticMode.SecureEnclave for modulo operations.");
}
