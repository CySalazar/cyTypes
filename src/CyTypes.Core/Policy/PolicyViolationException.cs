namespace CyTypes.Core.Policy;

/// <summary>
/// Exception thrown when an operation violates the security policy of a CyType instance.
/// </summary>
public sealed class PolicyViolationException : Exception
{
    /// <summary>Initializes a new instance with the specified error message.</summary>
    public PolicyViolationException(string message) : base(message) { }

    /// <summary>Initializes a new instance with the specified error message and inner exception.</summary>
    public PolicyViolationException(string message, Exception innerException) : base(message, innerException) { }
}
