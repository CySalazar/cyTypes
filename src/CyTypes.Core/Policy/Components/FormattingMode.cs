namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Controls whether formatted string output is allowed for CyType instances.
/// </summary>
public enum FormattingMode
{
    /// <summary>All formatting returns a redacted string. This is the default and most secure mode.</summary>
    Redacted = 0,
    /// <summary>Allows formatted output via IFormattable. Decryption occurs and the instance is marked as compromised.</summary>
    AllowFormatted = 1
}
