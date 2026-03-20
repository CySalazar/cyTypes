namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Controls how taint tracking propagates across operations involving encrypted values.
/// </summary>
public enum TaintMode
{
    /// <summary>Prevents cross-policy interaction unless explicitly allowed.</summary>
    Strict,

    /// <summary>Propagates taint information through operations using standard rules.</summary>
    Standard,

    /// <summary>Applies minimal taint tracking with no cross-policy restrictions.</summary>
    Relaxed
}
