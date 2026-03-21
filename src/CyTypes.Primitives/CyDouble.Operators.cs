using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

public sealed partial class CyDouble
{
    /// <summary>Implicitly converts a native <see cref="double"/> to a <see cref="CyDouble"/>.</summary>
    public static implicit operator CyDouble(double value) => new(value);
    /// <summary>Explicitly decrypts a <see cref="CyDouble"/> to a native <see cref="double"/>.</summary>
    public static explicit operator double(CyDouble cy) => cy.ToInsecureDouble();

    /// <summary>Adds two <see cref="CyDouble"/> values.</summary>
    public static CyDouble operator +(CyDouble left, CyDouble right) => BinaryOp(left, right, (a, b) => a + b);
    /// <summary>Subtracts two <see cref="CyDouble"/> values.</summary>
    public static CyDouble operator -(CyDouble left, CyDouble right) => BinaryOp(left, right, (a, b) => a - b);
    /// <summary>Multiplies two <see cref="CyDouble"/> values.</summary>
    public static CyDouble operator *(CyDouble left, CyDouble right) => BinaryOp(left, right, (a, b) => a * b);
    /// <summary>Divides two <see cref="CyDouble"/> values.</summary>
    public static CyDouble operator /(CyDouble left, CyDouble right) => BinaryOp(left, right, (a, b) => a / b);
    /// <summary>Computes the remainder of two <see cref="CyDouble"/> values.</summary>
    public static CyDouble operator %(CyDouble left, CyDouble right) => BinaryOp(left, right, (a, b) => a % b);

    // === Unary Operators ===

    /// <summary>Returns a new <see cref="CyDouble"/> with the same value (unary plus / identity).</summary>
    public static CyDouble operator +(CyDouble value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDouble(val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Negates the specified <see cref="CyDouble"/> value.</summary>
    public static CyDouble operator -(CyDouble value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDouble(-val, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Increments the specified <see cref="CyDouble"/> value by one.</summary>
    public static CyDouble operator ++(CyDouble value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDouble(val + 1d, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Decrements the specified <see cref="CyDouble"/> value by one.</summary>
    public static CyDouble operator --(CyDouble value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var val = value.DecryptValue();
        var result = new CyDouble(val - 1d, value.Policy);
        if (value.IsCompromised || value.IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>Determines whether two <see cref="CyDouble"/> instances are equal.</summary>
    public static bool operator ==(CyDouble? left, CyDouble? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return ConstantTimeEquals(left, right);
    }
    /// <summary>Determines whether two <see cref="CyDouble"/> instances are not equal.</summary>
    public static bool operator !=(CyDouble? left, CyDouble? right) => !(left == right);
    /// <summary>Determines whether the left <see cref="CyDouble"/> is less than the right.</summary>
    public static bool operator <(CyDouble left, CyDouble right) => CompareOp(left, right, (a, b) => a < b);
    /// <summary>Determines whether the left <see cref="CyDouble"/> is greater than the right.</summary>
    public static bool operator >(CyDouble left, CyDouble right) => CompareOp(left, right, (a, b) => a > b);
    /// <summary>Determines whether the left <see cref="CyDouble"/> is less than or equal to the right.</summary>
    public static bool operator <=(CyDouble left, CyDouble right) => CompareOp(left, right, (a, b) => a <= b);
    /// <summary>Determines whether the left <see cref="CyDouble"/> is greater than or equal to the right.</summary>
    public static bool operator >=(CyDouble left, CyDouble right) => CompareOp(left, right, (a, b) => a >= b);

    /// <inheritdoc/>
    public bool Equals(CyDouble? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyDouble);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();

    private static CyDouble BinaryOp(CyDouble left, CyDouble right, Func<double, double, double> op)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;
        var result = new CyDouble(op(left.DecryptValue(), right.DecryptValue()), resolved);
        if (taint) result.MarkTainted();
        return result;
    }

    private static bool CompareOp(CyDouble left, CyDouble right, Func<double, double, bool> op)
        => op(left.DecryptValue(), right.DecryptValue());

    private static bool ConstantTimeEquals(CyDouble left, CyDouble right)
        => ConstantTimeCompare.Equals(left.DecryptValue(), right.DecryptValue());
}
