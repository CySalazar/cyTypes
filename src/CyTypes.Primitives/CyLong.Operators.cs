using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

public sealed partial class CyLong
{
    private enum FheOp { Add, Subtract, Multiply, None }

    /// <summary>Implicitly converts a native <see cref="long"/> to a <see cref="CyLong"/>.</summary>
    public static implicit operator CyLong(long value) => new(value);
    /// <summary>Explicitly decrypts a <see cref="CyLong"/> to a native <see cref="long"/>.</summary>
    public static explicit operator long(CyLong cy) => cy.ToInsecureLong();

    /// <summary>Adds two <see cref="CyLong"/> values.</summary>
    public static CyLong operator +(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a + b, (a, b) => checked(a + b), FheOp.Add);
    /// <summary>Subtracts two <see cref="CyLong"/> values.</summary>
    public static CyLong operator -(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a - b, (a, b) => checked(a - b), FheOp.Subtract);
    /// <summary>Multiplies two <see cref="CyLong"/> values.</summary>
    public static CyLong operator *(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a * b, (a, b) => checked(a * b), FheOp.Multiply);
    /// <summary>Divides two <see cref="CyLong"/> values.</summary>
    public static CyLong operator /(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a / b, (a, b) => checked(a / b), FheOp.None);
    /// <summary>Computes the remainder of two <see cref="CyLong"/> values.</summary>
    public static CyLong operator %(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a % b, (a, b) => checked(a % b), FheOp.None);

    // === Unary Operators ===

    /// <summary>Returns a new <see cref="CyLong"/> with the same value (unary plus / identity).</summary>
    public static CyLong operator +(CyLong value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyLong(val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Negates the specified <see cref="CyLong"/> value.</summary>
    public static CyLong operator -(CyLong value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyLong(-val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Increments the specified <see cref="CyLong"/> value by one.</summary>
    public static CyLong operator ++(CyLong value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyLong(val + 1, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Decrements the specified <see cref="CyLong"/> value by one.</summary>
    public static CyLong operator --(CyLong value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyLong(val - 1, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Determines whether two <see cref="CyLong"/> instances are equal.</summary>
    public static bool operator ==(CyLong? left, CyLong? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return ConstantTimeEquals(left, right);
    }
    /// <summary>Determines whether two <see cref="CyLong"/> instances are not equal.</summary>
    public static bool operator !=(CyLong? left, CyLong? right) => !(left == right);
    /// <summary>Determines whether the left <see cref="CyLong"/> is less than the right.</summary>
    public static bool operator <(CyLong left, CyLong right) => CompareOp(left, right, (a, b) => a < b);
    /// <summary>Determines whether the left <see cref="CyLong"/> is greater than the right.</summary>
    public static bool operator >(CyLong left, CyLong right) => CompareOp(left, right, (a, b) => a > b);
    /// <summary>Determines whether the left <see cref="CyLong"/> is less than or equal to the right.</summary>
    public static bool operator <=(CyLong left, CyLong right) => CompareOp(left, right, (a, b) => a <= b);
    /// <summary>Determines whether the left <see cref="CyLong"/> is greater than or equal to the right.</summary>
    public static bool operator >=(CyLong left, CyLong right) => CompareOp(left, right, (a, b) => a >= b);

    // === Bitwise Operators ===

    /// <summary>Computes the bitwise AND of two <see cref="CyLong"/> values.</summary>
    public static CyLong operator &(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a & b, (a, b) => a & b, FheOp.None);
    /// <summary>Computes the bitwise OR of two <see cref="CyLong"/> values.</summary>
    public static CyLong operator |(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a | b, (a, b) => a | b, FheOp.None);
    /// <summary>Computes the bitwise XOR of two <see cref="CyLong"/> values.</summary>
    public static CyLong operator ^(CyLong left, CyLong right) => BinaryOp(left, right, (a, b) => a ^ b, (a, b) => a ^ b, FheOp.None);

    /// <summary>Computes the bitwise complement of the <see cref="CyLong"/> value.</summary>
    public static CyLong operator ~(CyLong value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyLong(~val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Left-shifts the <see cref="CyLong"/> value by the specified amount.</summary>
    public static CyLong operator <<(CyLong left, int shift)
    {
        ArgumentNullException.ThrowIfNull(left);
        var val = left.DecryptValue();
        var result = new CyLong(val << shift, left.Policy);
        if (left.IsCompromised || left.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Right-shifts the <see cref="CyLong"/> value by the specified amount.</summary>
    public static CyLong operator >>(CyLong left, int shift)
    {
        ArgumentNullException.ThrowIfNull(left);
        var val = left.DecryptValue();
        var result = new CyLong(val >> shift, left.Policy);
        if (left.IsCompromised || left.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Unsigned right-shifts the <see cref="CyLong"/> value by the specified amount.</summary>
    public static CyLong operator >>>(CyLong left, int shift)
    {
        ArgumentNullException.ThrowIfNull(left);
        var val = left.DecryptValue();
        var result = new CyLong(val >>> shift, left.Policy);
        if (left.IsCompromised || left.IsTainted) result.MarkTainted();
        return result;
    }

    /// <inheritdoc/>
    public bool Equals(CyLong? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyLong);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();

    private static CyLong BinaryOp(CyLong left, CyLong right, Func<long, long, long> op, Func<long, long, long> checkedOp, FheOp fheOp)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;

        // FHE path
        if (fheOp != FheOp.None && left.IsFheMode && right.IsFheMode &&
            resolved.Arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull)
        {
            var engine = FheEngineProvider.Current
                ?? throw new InvalidOperationException("FHE engine not configured. Register via AddCyTypesFhe().");

            var leftBytes = left.GetEncryptedBytes();
            var rightBytes = right.GetEncryptedBytes();

            var resultBytes = fheOp switch
            {
                FheOp.Add => engine.Add(leftBytes, rightBytes),
                FheOp.Subtract => engine.Subtract(leftBytes, rightBytes),
                FheOp.Multiply => engine.Multiply(leftBytes, rightBytes),
                _ => throw new InvalidOperationException($"Unexpected FHE operation: {fheOp}")
            };

            var result = new CyLong(resultBytes, resolved);
            if (taint) result.MarkTainted();
            return result;
        }

        // SecureEnclave path
        var actualOp = resolved.Overflow == OverflowMode.Checked ? checkedOp : op;
        var enclaveResult = new CyLong(actualOp(left.DecryptValue(), right.DecryptValue()), resolved);
        if (taint) enclaveResult.MarkTainted();
        return enclaveResult;
    }

    private static bool CompareOp(CyLong left, CyLong right, Func<long, long, bool> op)
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

    private static bool ConstantTimeEquals(CyLong left, CyLong right)
    {
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        if (resolved.Comparison == ComparisonMode.HomomorphicCircuit &&
            left.IsFheMode && right.IsFheMode)
        {
            var compEngine = FheEngineProvider.GetComparisonEngine()
                ?? throw new InvalidOperationException("FHE comparison engine not configured.");
            var diff = compEngine.ComputeDifference(left.GetEncryptedBytes(), right.GetEncryptedBytes());
            return compEngine.DecryptEquality(diff);
        }

        return ConstantTimeCompare.Equals(left.DecryptValue(), right.DecryptValue());
    }
}
