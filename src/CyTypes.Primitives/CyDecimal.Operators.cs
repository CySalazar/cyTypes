using CyTypes.Core.Policy;

namespace CyTypes.Primitives;

public sealed partial class CyDecimal
{
    /// <summary>Implicitly converts a <see cref="decimal"/> to a <see cref="CyDecimal"/>.</summary>
    public static implicit operator CyDecimal(decimal value) => new(value);
    /// <summary>Explicitly converts a <see cref="CyDecimal"/> to a <see cref="decimal"/>. Marks compromise.</summary>
    public static explicit operator decimal(CyDecimal cy) => cy.ToInsecureDecimal();

    /// <summary>Adds two <see cref="CyDecimal"/> values.</summary>
    public static CyDecimal operator +(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a + b);
    /// <summary>Subtracts the right <see cref="CyDecimal"/> from the left.</summary>
    public static CyDecimal operator -(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a - b);
    /// <summary>Multiplies two <see cref="CyDecimal"/> values.</summary>
    public static CyDecimal operator *(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a * b);
    /// <summary>Divides the left <see cref="CyDecimal"/> by the right.</summary>
    public static CyDecimal operator /(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a / b);
    /// <summary>Returns the remainder of dividing the left <see cref="CyDecimal"/> by the right.</summary>
    public static CyDecimal operator %(CyDecimal left, CyDecimal right) => BinaryOp(left, right, (a, b) => a % b);

    /// <summary>Determines whether two <see cref="CyDecimal"/> instances are equal.</summary>
    public static bool operator ==(CyDecimal? left, CyDecimal? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return CompareOp(left, right, (a, b) => a == b);
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
    /// <inheritdoc/>
    public override int GetHashCode() => InstanceId.GetHashCode();

    private static CyDecimal BinaryOp(CyDecimal left, CyDecimal right, Func<decimal, decimal, decimal> op)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;
        var result = new CyDecimal(op(left.DecryptValue(), right.DecryptValue()), resolved);
        if (taint) result.MarkTainted();
        return result;
    }

    private static bool CompareOp(CyDecimal left, CyDecimal right, Func<decimal, decimal, bool> op)
        => op(left.DecryptValue(), right.DecryptValue());
}
