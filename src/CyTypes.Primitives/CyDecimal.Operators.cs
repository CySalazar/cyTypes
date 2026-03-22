using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

public sealed partial class CyDecimal
{
    private enum FheOp { Add, Subtract, Multiply, None }

    /// <summary>Implicitly converts a <see cref="decimal"/> to a <see cref="CyDecimal"/>.</summary>
    public static implicit operator CyDecimal(decimal value) => new(value);
    /// <summary>Explicitly converts a <see cref="CyDecimal"/> to a <see cref="decimal"/>. Marks compromise.</summary>
    public static explicit operator decimal(CyDecimal cy) => cy.ToInsecureDecimal();

    /// <summary>Adds two <see cref="CyDecimal"/> values.</summary>
    public static CyDecimal operator +(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a + b, FheOp.Add);
    /// <summary>Subtracts the right <see cref="CyDecimal"/> from the left.</summary>
    public static CyDecimal operator -(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a - b, FheOp.Subtract);
    /// <summary>Multiplies two <see cref="CyDecimal"/> values.</summary>
    public static CyDecimal operator *(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a * b, FheOp.Multiply);
    /// <summary>Divides the left <see cref="CyDecimal"/> by the right.</summary>
    public static CyDecimal operator /(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a / b, FheOp.None);
    /// <summary>Returns the remainder of dividing the left <see cref="CyDecimal"/> by the right.</summary>
    public static CyDecimal operator %(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a % b, FheOp.None);

    // === Unary Operators ===

    /// <summary>Returns a new <see cref="CyDecimal"/> with the same value (unary plus / identity).</summary>
    public static CyDecimal operator +(CyDecimal value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDecimal(val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Negates the specified <see cref="CyDecimal"/> value.</summary>
    public static CyDecimal operator -(CyDecimal value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDecimal(-val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Increments the specified <see cref="CyDecimal"/> value by one.</summary>
    public static CyDecimal operator ++(CyDecimal value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDecimal(val + 1m, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Decrements the specified <see cref="CyDecimal"/> value by one.</summary>
    public static CyDecimal operator --(CyDecimal value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDecimal(val - 1m, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Determines whether two <see cref="CyDecimal"/> instances are equal.</summary>
    public static bool operator ==(CyDecimal? left, CyDecimal? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return ConstantTimeEquals(left, right);
    }
    /// <summary>Determines whether two <see cref="CyDecimal"/> instances are not equal.</summary>
    public static bool operator !=(CyDecimal? left, CyDecimal? right) => !(left == right);
    /// <summary>Determines whether the left <see cref="CyDecimal"/> is less than the right.</summary>
    public static bool operator <(CyDecimal left, CyDecimal right) => CompareOp(left, right, (a, b) => a < b);
    /// <summary>Determines whether the left <see cref="CyDecimal"/> is greater than the right.</summary>
    public static bool operator >(CyDecimal left, CyDecimal right) => CompareOp(left, right, (a, b) => a > b);
    /// <summary>Determines whether the left <see cref="CyDecimal"/> is less than or equal to the right.</summary>
    public static bool operator <=(CyDecimal left, CyDecimal right) => CompareOp(left, right, (a, b) => a <= b);
    /// <summary>Determines whether the left <see cref="CyDecimal"/> is greater than or equal to the right.</summary>
    public static bool operator >=(CyDecimal left, CyDecimal right) => CompareOp(left, right, (a, b) => a >= b);

    /// <inheritdoc/>
    public bool Equals(CyDecimal? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyDecimal);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();

    private static CyDecimal BinaryOp(CyDecimal left, CyDecimal right, Func<decimal, decimal, decimal> op, FheOp fheOp)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;

        // FHE path: operate directly on ciphertexts via CKKS engine
        // NOTE: CKKS approximate arithmetic means decimal precision (28-29 digits) is NOT preserved.
        if (fheOp != FheOp.None && left.IsFheMode && right.IsFheMode &&
            resolved.Arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull)
        {
            var engine = FheEngineProvider.GetFloatingPointEngine()
                ?? throw new InvalidOperationException("CKKS FHE engine not configured. Register via AddCyTypesCkks().");

            var leftBytes = left.GetEncryptedBytes();
            var rightBytes = right.GetEncryptedBytes();

            var resultBytes = fheOp switch
            {
                FheOp.Add => engine.Add(leftBytes, rightBytes),
                FheOp.Subtract => engine.Subtract(leftBytes, rightBytes),
                FheOp.Multiply => engine.Multiply(leftBytes, rightBytes),
                _ => throw new InvalidOperationException($"Unexpected FHE operation: {fheOp}")
            };

            var result = new CyDecimal(resultBytes, resolved);
            if (taint) result.MarkTainted();
            return result;
        }

        // SecureEnclave path: decrypt, compute, re-encrypt
        var enclaveResult = new CyDecimal(op(left.DecryptValue(), right.DecryptValue()), resolved);
        if (taint) enclaveResult.MarkTainted();
        return enclaveResult;
    }

    private static bool CompareOp(CyDecimal left, CyDecimal right, Func<decimal, decimal, bool> op)
    {
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        if (resolved.Comparison == ComparisonMode.HomomorphicCircuit &&
            left.IsFheMode && right.IsFheMode)
        {
            var compEngine = FheEngineProvider.GetComparisonEngine()
                ?? throw new InvalidOperationException("FHE comparison engine not configured.");
            var diff = compEngine.ComputeDifference(left.GetEncryptedBytes(), right.GetEncryptedBytes());
            var sign = compEngine.DecryptComparison(diff);
            return op(sign, 0);
        }

        return op(left.DecryptValue(), right.DecryptValue());
    }

    private static bool ConstantTimeEquals(CyDecimal left, CyDecimal right)
    {
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        if (resolved.Comparison == ComparisonMode.HomomorphicCircuit &&
            left.IsFheMode && right.IsFheMode)
        {
            var compEngine = FheEngineProvider.GetComparisonEngine()
                ?? throw new InvalidOperationException("FHE comparison engine not configured.");
            var diff = compEngine.ComputeDifference(left.GetEncryptedBytes(), right.GetEncryptedBytes());
            return compEngine.DecryptEquality(diff, 1e-7);
        }

        return ConstantTimeCompare.Equals(left.DecryptValue(), right.DecryptValue());
    }
}
