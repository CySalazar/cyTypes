namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Defines when encryption keys are rotated for a CyType instance.
/// </summary>
public sealed class KeyRotationPolicy
{
    /// <summary>Gets the kind of key rotation schedule.</summary>
    public KeyRotationKind Kind { get; }

    /// <summary>Gets the numeric parameter for the rotation schedule, or zero for manual rotation.</summary>
    public int Value { get; }

    private KeyRotationPolicy(KeyRotationKind kind, int value = 0)
    {
        Kind = kind;
        Value = value;
    }

    /// <summary>Creates a policy that rotates the key every <paramref name="n"/> operations.</summary>
    public static KeyRotationPolicy EveryNOperations(int n)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(n, 0);
        return new KeyRotationPolicy(KeyRotationKind.EveryNOperations, n);
    }

    /// <summary>Creates a policy that rotates the key every <paramref name="n"/> minutes.</summary>
    public static KeyRotationPolicy EveryNMinutes(int n)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(n, 0);
        return new KeyRotationPolicy(KeyRotationKind.EveryNMinutes, n);
    }

    /// <summary>Gets a policy that requires manual key rotation.</summary>
    public static KeyRotationPolicy Manual { get; } = new(KeyRotationKind.Manual);

    /// <summary>Creates a policy that rotates the key at the specified time interval.</summary>
    public static KeyRotationPolicy EveryTimeSpan(TimeSpan interval)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(interval, TimeSpan.Zero);
        return new KeyRotationPolicy(KeyRotationKind.EveryNMinutes, (int)interval.TotalMinutes);
    }

    /// <summary>Returns a human-readable description of the rotation policy.</summary>
    public override string ToString() => Kind switch
    {
        KeyRotationKind.EveryNOperations => $"Every {Value} operations",
        KeyRotationKind.EveryNMinutes => $"Every {Value} minutes",
        KeyRotationKind.Manual => "Manual",
        _ => "Unknown"
    };
}

/// <summary>
/// Identifies the kind of key rotation schedule.
/// </summary>
public enum KeyRotationKind
{
    /// <summary>Rotate the key after a fixed number of operations.</summary>
    EveryNOperations,

    /// <summary>Rotate the key after a fixed number of minutes.</summary>
    EveryNMinutes,

    /// <summary>Key rotation is performed manually by the caller.</summary>
    Manual
}
