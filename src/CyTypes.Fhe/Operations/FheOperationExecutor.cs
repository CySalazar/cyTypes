using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Fhe.NoiseBudget;

namespace CyTypes.Fhe.Operations;

/// <summary>
/// Executes FHE arithmetic operations (add, subtract, multiply, negate)
/// by delegating to an <see cref="IFheEngine"/> and tracking noise budget.
/// </summary>
public sealed class FheOperationExecutor
{
    private readonly IFheEngine _engine;
    private readonly NoiseBudgetTracker? _tracker;

    /// <summary>Initializes a new executor with the specified FHE engine.</summary>
    public FheOperationExecutor(IFheEngine engine, NoiseBudgetTracker? tracker = null)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _tracker = tracker;
    }

    /// <summary>Performs homomorphic addition on two ciphertexts.</summary>
    public byte[] Add(byte[] a, byte[] b)
    {
        var result = _engine.Add(a, b);
        _tracker?.CheckBudget(result);
        return result;
    }

    /// <summary>Performs homomorphic subtraction on two ciphertexts.</summary>
    public byte[] Subtract(byte[] a, byte[] b)
    {
        var result = _engine.Subtract(a, b);
        _tracker?.CheckBudget(result);
        return result;
    }

    /// <summary>Performs homomorphic multiplication on two ciphertexts.</summary>
    public byte[] Multiply(byte[] a, byte[] b)
    {
        var result = _engine.Multiply(a, b);
        _tracker?.CheckBudget(result);
        return result;
    }

    /// <summary>Performs homomorphic negation on a ciphertext.</summary>
    public byte[] Negate(byte[] a)
    {
        var result = _engine.Negate(a);
        _tracker?.CheckBudget(result);
        return result;
    }

    /// <summary>
    /// Division is not supported in BFV FHE. Use SecureEnclave mode instead.
    /// </summary>
    public byte[] Divide(byte[] a, byte[] b) =>
        throw new NotSupportedException(
            "FHE does not support integer division. Use ArithmeticMode.SecureEnclave for division operations.");

    /// <summary>
    /// Modulo is not supported in BFV FHE. Use SecureEnclave mode instead.
    /// </summary>
    public byte[] Modulo(byte[] a, byte[] b) =>
        throw new NotSupportedException(
            "FHE does not support modulo operations. Use ArithmeticMode.SecureEnclave for modulo operations.");
}
