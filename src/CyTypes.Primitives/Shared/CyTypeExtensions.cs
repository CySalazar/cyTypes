using CyTypes.Core.Policy;

namespace CyTypes.Primitives.Shared;

/// <summary>Extension methods for <see cref="ICyType"/> instances.</summary>
public static class CyTypeExtensions
{
    /// <summary>Returns true if both instances share the same security policy (by reference or name).</summary>
    public static bool HasSamePolicy(this ICyType a, ICyType b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        return ReferenceEquals(a.Policy, b.Policy) || a.Policy.Name == b.Policy.Name;
    }

    /// <summary>Resolves the effective policy for a binary operation between two CyType instances.</summary>
    public static SecurityPolicy ResolvePolicy(this ICyType a, ICyType b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        return PolicyResolver.Resolve(a.Policy, b.Policy);
    }
}
