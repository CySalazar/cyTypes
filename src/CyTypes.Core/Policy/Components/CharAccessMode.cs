namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Controls the security behavior when accessing individual characters of a CyString.
/// </summary>
public enum CharAccessMode
{
    /// <summary>Accessing a character marks the instance as compromised (default, most secure).</summary>
    CompromiseOnAccess = 0,
    /// <summary>Accessing a character marks the instance as tainted instead of compromised.</summary>
    TaintOnAccess = 1
}
