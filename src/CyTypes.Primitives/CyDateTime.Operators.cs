namespace CyTypes.Primitives;

public sealed partial class CyDateTime
{
    /// <summary>Implicitly converts a <see cref="DateTime"/> to a <see cref="CyDateTime"/>.</summary>
    public static implicit operator CyDateTime(DateTime value) => new(value);
    /// <summary>Explicitly converts a <see cref="CyDateTime"/> to a <see cref="DateTime"/>. Marks compromise.</summary>
    public static explicit operator DateTime(CyDateTime cy) => cy.ToInsecureDateTime();

    /// <summary>Determines whether two <see cref="CyDateTime"/> instances are equal.</summary>
    public static bool operator ==(CyDateTime? left, CyDateTime? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return CompareOp(left, right, (a, b) => a == b);
    }
    /// <summary>Determines whether two <see cref="CyDateTime"/> instances are not equal.</summary>
    public static bool operator !=(CyDateTime? left, CyDateTime? right) => !(left == right);
    /// <summary>Determines whether the left <see cref="CyDateTime"/> is earlier than the right.</summary>
    public static bool operator <(CyDateTime left, CyDateTime right) => CompareOp(left, right, (a, b) => a < b);
    /// <summary>Determines whether the left <see cref="CyDateTime"/> is later than the right.</summary>
    public static bool operator >(CyDateTime left, CyDateTime right) => CompareOp(left, right, (a, b) => a > b);
    /// <summary>Determines whether the left <see cref="CyDateTime"/> is earlier than or equal to the right.</summary>
    public static bool operator <=(CyDateTime left, CyDateTime right) => CompareOp(left, right, (a, b) => a <= b);
    /// <summary>Determines whether the left <see cref="CyDateTime"/> is later than or equal to the right.</summary>
    public static bool operator >=(CyDateTime left, CyDateTime right) => CompareOp(left, right, (a, b) => a >= b);

    /// <inheritdoc/>
    public bool Equals(CyDateTime? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyDateTime);
    /// <inheritdoc/>
    public override int GetHashCode() => InstanceId.GetHashCode();

    private static bool CompareOp(CyDateTime left, CyDateTime right, Func<DateTime, DateTime, bool> op)
        => op(left.DecryptValue(), right.DecryptValue());
}
