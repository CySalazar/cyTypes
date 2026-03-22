using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

public sealed partial class CyFloat
{
    private enum FheOp { Add, Subtract, Multiply, None }

    /// <summary>Implicitly converts a native <see cref="float"/> to a <see cref="CyFloat"/>.</summary>
    public static implicit operator CyFloat(float value) => new(value);
    /// <summary>Explicitly decrypts a <see cref="CyFloat"/> to a native <see cref="float"/>.</summary>
    public static explicit operator float(CyFloat cy) => cy.ToInsecureFloat();

    /// <summary>Adds two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator +(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a + b, FheOp.Add);
    /// <summary>Subtracts two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator -(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a - b, FheOp.Subtract);
    /// <summary>Multiplies two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator *(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a * b, FheOp.Multiply);
    /// <summary>Divides two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator /(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a / b, FheOp.None);
    /// <summary>Computes the remainder of two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator %(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a % b, FheOp.None);

    // === Unary Operators ===

    /// <summary>Returns a new <see cref="CyFloat"/> with the same value (unary plus / identity).</summary>
    public static CyFloat operator +(CyFloat value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyFloat(val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Negates the specified <see cref="CyFloat"/> value.</summary>
    public static CyFloat operator -(CyFloat value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyFloat(-val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Increments the specified <see cref="CyFloat"/> value by one.</summary>
    public static CyFloat operator ++(CyFloat value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyFloat(val + 1f, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Decrements the specified <see cref="CyFloat"/> value by one.</summary>
    public static CyFloat operator --(CyFloat value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyFloat(val - 1f, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Determines whether two <see cref="CyFloat"/> instances are equal.</summary>
    public static bool operator ==(CyFloat? left, CyFloat? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return ConstantTimeEquals(left, right);
    }
    /// <summary>Determines whether two <see cref="CyFloat"/> instances are not equal.</summary>
    public static bool operator !=(CyFloat? left, CyFloat? right) => !(left == right);
    /// <summary>Determines whether the left <see cref="CyFloat"/> is less than the right.</summary>
    public static bool operator <(CyFloat left, CyFloat right) => CompareOp(left, right, (a, b) => a < b);
    /// <summary>Determines whether the left <see cref="CyFloat"/> is greater than the right.</summary>
    public static bool operator >(CyFloat left, CyFloat right) => CompareOp(left, right, (a, b) => a > b);
    /// <summary>Determines whether the left <see cref="CyFloat"/> is less than or equal to the right.</summary>
    public static bool operator <=(CyFloat left, CyFloat right) => CompareOp(left, right, (a, b) => a <= b);
    /// <summary>Determines whether the left <see cref="CyFloat"/> is greater than or equal to the right.</summary>
    public static bool operator >=(CyFloat left, CyFloat right) => CompareOp(left, right, (a, b) => a >= b);

    // === Implicit Widening Conversions ===

    /// <summary>Implicitly widens a <see cref="CyFloat"/> to a <see cref="CyDouble"/>.</summary>
    public static implicit operator CyDouble(CyFloat cy)
    {
        ArgumentNullException.ThrowIfNull(cy);
        return new CyDouble(cy.DecryptValue(), cy.Policy);
    }

    /// <inheritdoc/>
    public bool Equals(CyFloat? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyFloat);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();

    private static CyFloat BinaryOp(CyFloat left, CyFloat right, Func<float, float, float> op, FheOp fheOp)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;

        // FHE path: operate directly on ciphertexts via CKKS engine
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

            var result = new CyFloat(resultBytes, resolved);
            if (taint) result.MarkTainted();
            return result;
        }

        // SecureEnclave path: decrypt, compute, re-encrypt
        var enclaveResult = new CyFloat(op(left.DecryptValue(), right.DecryptValue()), resolved);
        if (taint) enclaveResult.MarkTainted();
        return enclaveResult;
    }

    private static bool CompareOp(CyFloat left, CyFloat right, Func<float, float, bool> op)
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

    private static bool ConstantTimeEquals(CyFloat left, CyFloat right)
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
