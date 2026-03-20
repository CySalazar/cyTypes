using CyTypes.Core.Policy;

namespace CyTypes.Primitives;

public sealed partial class CyBool
{
    /// <summary>Implicitly converts a <see cref="bool"/> to a <see cref="CyBool"/>.</summary>
    public static implicit operator CyBool(bool value) => new(value);
    /// <summary>Explicitly converts a <see cref="CyBool"/> to a <see cref="bool"/>. Marks compromise.</summary>
    public static explicit operator bool(CyBool cy) => cy.ToInsecureBool();

    /// <summary>Performs a bitwise AND on two <see cref="CyBool"/> values.</summary>
    public static CyBool operator &(CyBool left, CyBool right) => LogicOp(left, right, (a, b) => a & b);
    /// <summary>Performs a bitwise OR on two <see cref="CyBool"/> values.</summary>
    public static CyBool operator |(CyBool left, CyBool right) => LogicOp(left, right, (a, b) => a | b);
    /// <summary>Performs a bitwise XOR on two <see cref="CyBool"/> values.</summary>
    public static CyBool operator ^(CyBool left, CyBool right) => LogicOp(left, right, (a, b) => a ^ b);
    /// <summary>Negates the specified <see cref="CyBool"/> value.</summary>
    public static CyBool operator !(CyBool operand)
    {
        ArgumentNullException.ThrowIfNull(operand);
        var taint = operand.IsCompromised || operand.IsTainted;
        var result = new CyBool(!operand.DecryptValue(), operand.Policy);
        if (taint) result.MarkTainted();
        return result;
    }

    /// <summary>Determines whether two <see cref="CyBool"/> instances are equal.</summary>
    public static bool operator ==(CyBool? left, CyBool? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return left.DecryptValue() == right.DecryptValue();
    }
    /// <summary>Determines whether two <see cref="CyBool"/> instances are not equal.</summary>
    public static bool operator !=(CyBool? left, CyBool? right) => !(left == right);

    /// <summary>Less-than comparison (false &lt; true).</summary>
    public static bool operator <(CyBool left, CyBool right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) < 0;
    }

    /// <summary>Greater-than comparison (true &gt; false).</summary>
    public static bool operator >(CyBool left, CyBool right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) > 0;
    }

    /// <summary>Less-than-or-equal comparison.</summary>
    public static bool operator <=(CyBool left, CyBool right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) <= 0;
    }

    /// <summary>Greater-than-or-equal comparison.</summary>
    public static bool operator >=(CyBool left, CyBool right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) >= 0;
    }

    /// <inheritdoc/>
    public bool Equals(CyBool? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyBool);
    /// <inheritdoc/>
    public override int GetHashCode() => InstanceId.GetHashCode();

    private static CyBool LogicOp(CyBool left, CyBool right, Func<bool, bool, bool> op)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;
        var result = new CyBool(op(left.DecryptValue(), right.DecryptValue()), resolved);
        if (taint) result.MarkTainted();
        return result;
    }
}
