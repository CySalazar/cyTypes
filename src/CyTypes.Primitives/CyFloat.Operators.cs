using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

public sealed partial class CyFloat
{
    /// <summary>Implicitly converts a native <see cref="float"/> to a <see cref="CyFloat"/>.</summary>
    public static implicit operator CyFloat(float value) => new(value);
    /// <summary>Explicitly decrypts a <see cref="CyFloat"/> to a native <see cref="float"/>.</summary>
    public static explicit operator float(CyFloat cy) => cy.ToInsecureFloat();

    /// <summary>Adds two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator +(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a + b);
    /// <summary>Subtracts two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator -(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a - b);
    /// <summary>Multiplies two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator *(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a * b);
    /// <summary>Divides two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator /(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a / b);
    /// <summary>Computes the remainder of two <see cref="CyFloat"/> values.</summary>
    public static CyFloat operator %(CyFloat left, CyFloat right) => BinaryOp(left, right, (a, b) => a % b);

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

    private static CyFloat BinaryOp(CyFloat left, CyFloat right, Func<float, float, float> op)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;
        var result = new CyFloat(op(left.DecryptValue(), right.DecryptValue()), resolved);
        if (taint) result.MarkTainted();
        return result;
    }

    private static bool CompareOp(CyFloat left, CyFloat right, Func<float, float, bool> op)
        => op(left.DecryptValue(), right.DecryptValue());

    private static bool ConstantTimeEquals(CyFloat left, CyFloat right)
        => ConstantTimeCompare.Equals(left.DecryptValue(), right.DecryptValue());
}
