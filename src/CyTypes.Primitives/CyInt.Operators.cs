using System.Security.Cryptography;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

public sealed partial class CyInt
{
    private enum FheOp { Add, Subtract, Multiply, None }

    // === Implicit/Explicit Conversions ===

    /// <summary>Encrypts a native int into a CyInt (safe, uses Balanced policy).</summary>
    public static implicit operator CyInt(int value) => new(value);

    /// <summary>Decrypts the CyInt to a native int. Marks compromise.</summary>
    public static explicit operator int(CyInt cy) => cy.ToInsecureInt();

    // === Arithmetic Operators ===

    /// <summary>Adds two <see cref="CyInt"/> values.</summary>
    public static CyInt operator +(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a + b, (a, b) => checked(a + b), FheOp.Add);
    }

    /// <summary>Subtracts two <see cref="CyInt"/> values.</summary>
    public static CyInt operator -(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a - b, (a, b) => checked(a - b), FheOp.Subtract);
    }

    /// <summary>Multiplies two <see cref="CyInt"/> values.</summary>
    public static CyInt operator *(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a * b, (a, b) => checked(a * b), FheOp.Multiply);
    }

    /// <summary>Divides two <see cref="CyInt"/> values.</summary>
    public static CyInt operator /(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a / b, (a, b) => checked(a / b), FheOp.None);
    }

    /// <summary>Computes the remainder of two <see cref="CyInt"/> values.</summary>
    public static CyInt operator %(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a % b, (a, b) => checked(a % b), FheOp.None);
    }

    // === Unary Operators ===

    /// <summary>Returns a new <see cref="CyInt"/> with the same value (unary plus / identity).</summary>
    public static CyInt operator +(CyInt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyInt(val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Negates the specified <see cref="CyInt"/> value.</summary>
    public static CyInt operator -(CyInt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyInt(-val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Increments the specified <see cref="CyInt"/> value by one.</summary>
    public static CyInt operator ++(CyInt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyInt(val + 1, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Decrements the specified <see cref="CyInt"/> value by one.</summary>
    public static CyInt operator --(CyInt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyInt(val - 1, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    // === Comparison Operators ===

    /// <summary>Determines whether two <see cref="CyInt"/> instances are equal.</summary>
    public static bool operator ==(CyInt? left, CyInt? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return ConstantTimeEquals(left, right);
    }

    /// <summary>Determines whether two <see cref="CyInt"/> instances are not equal.</summary>
    public static bool operator !=(CyInt? left, CyInt? right) => !(left == right);

    /// <summary>Determines whether the left <see cref="CyInt"/> is less than the right.</summary>
    public static bool operator <(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return CompareOp(left, right, (a, b) => a < b);
    }

    /// <summary>Determines whether the left <see cref="CyInt"/> is greater than the right.</summary>
    public static bool operator >(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return CompareOp(left, right, (a, b) => a > b);
    }

    /// <summary>Determines whether the left <see cref="CyInt"/> is less than or equal to the right.</summary>
    public static bool operator <=(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return CompareOp(left, right, (a, b) => a <= b);
    }

    /// <summary>Determines whether the left <see cref="CyInt"/> is greater than or equal to the right.</summary>
    public static bool operator >=(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return CompareOp(left, right, (a, b) => a >= b);
    }

    /// <inheritdoc/>
    public bool Equals(CyInt? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyInt);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();

    // === Bitwise Operators ===

    /// <summary>Computes the bitwise AND of two <see cref="CyInt"/> values.</summary>
    public static CyInt operator &(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a & b, (a, b) => a & b, FheOp.None);
    }

    /// <summary>Computes the bitwise OR of two <see cref="CyInt"/> values.</summary>
    public static CyInt operator |(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a | b, (a, b) => a | b, FheOp.None);
    }

    /// <summary>Computes the bitwise XOR of two <see cref="CyInt"/> values.</summary>
    public static CyInt operator ^(CyInt left, CyInt right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return BinaryOp(left, right, (a, b) => a ^ b, (a, b) => a ^ b, FheOp.None);
    }

    /// <summary>Computes the bitwise complement of the <see cref="CyInt"/> value.</summary>
    public static CyInt operator ~(CyInt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyInt(~val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Left-shifts the <see cref="CyInt"/> value by the specified amount.</summary>
    public static CyInt operator <<(CyInt left, int shift)
    {
        ArgumentNullException.ThrowIfNull(left);
        var val = left.DecryptValue();
        var result = new CyInt(val << shift, left.Policy);
        if (left.IsCompromised || left.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Right-shifts the <see cref="CyInt"/> value by the specified amount.</summary>
    public static CyInt operator >>(CyInt left, int shift)
    {
        ArgumentNullException.ThrowIfNull(left);
        var val = left.DecryptValue();
        var result = new CyInt(val >> shift, left.Policy);
        if (left.IsCompromised || left.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Unsigned right-shifts the <see cref="CyInt"/> value by the specified amount.</summary>
    public static CyInt operator >>>(CyInt left, int shift)
    {
        ArgumentNullException.ThrowIfNull(left);
        var val = left.DecryptValue();
        var result = new CyInt(val >>> shift, left.Policy);
        if (left.IsCompromised || left.IsTainted) result.MarkTainted();
        return result;
    }

    // === Implicit Widening Conversions ===

    /// <summary>Implicitly widens a <see cref="CyInt"/> to a <see cref="CyLong"/>.</summary>
    public static implicit operator CyLong(CyInt cy)
    {
        ArgumentNullException.ThrowIfNull(cy);
        return new CyLong(cy.DecryptValue(), cy.Policy);
    }

    /// <summary>Implicitly widens a <see cref="CyInt"/> to a <see cref="CyDouble"/>.</summary>
    public static implicit operator CyDouble(CyInt cy)
    {
        ArgumentNullException.ThrowIfNull(cy);
        return new CyDouble(cy.DecryptValue(), cy.Policy);
    }

    // === Internal Helpers ===

    private static CyInt BinaryOp(CyInt left, CyInt right, Func<int, int, int> op, Func<int, int, int> checkedOp, FheOp fheOp)
    {
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);

        // SECURITY: Taint propagation — if either operand is compromised/tainted, result is tainted
        var taintResult = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;

        // FHE path: operate directly on ciphertexts without decryption
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

            var result = new CyInt(resultBytes, resolved);
            if (taintResult) result.MarkTainted();
            return result;
        }

        // SecureEnclave path: decrypt, compute, re-encrypt
        var leftVal = left.DecryptValue();
        var rightVal = right.DecryptValue();

        var actualOp = resolved.Overflow == OverflowMode.Checked ? checkedOp : op;
        var resultValue = actualOp(leftVal, rightVal);
        var enclaveResult = new CyInt(resultValue, resolved);

        if (taintResult)
            enclaveResult.MarkTainted();

        return enclaveResult;
    }

    private static bool CompareOp(CyInt left, CyInt right, Func<int, int, bool> op)
    {
        // HomomorphicCircuit path: compute encrypted difference, extract sign at decrypt
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

    // SECURITY: Constant-time equality to prevent timing side-channel attacks
    private static bool ConstantTimeEquals(CyInt left, CyInt right)
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
