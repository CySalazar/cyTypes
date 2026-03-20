namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Controls integer arithmetic overflow behavior in CyInt and CyLong operations.
/// Floating-point types (CyFloat, CyDouble) are unaffected (IEEE 754 semantics).
/// CyDecimal always throws on overflow regardless of this setting.
/// </summary>
public enum OverflowMode
{
    /// <summary>Throw <see cref="OverflowException"/> on integer overflow (safer, recommended for financial/security).</summary>
    Checked,

    /// <summary>Silently wrap on integer overflow (matches native .NET unchecked behavior).</summary>
    Unchecked
}
