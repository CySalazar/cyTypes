namespace CyTypes.Core.Security;

/// <summary>Categorizes the types of security events that a CyType instance can raise.</summary>
public enum SecurityEventType
{
    /// <summary>A new CyType instance was created.</summary>
    Created,
    /// <summary>The encrypted value was decrypted.</summary>
    Decrypted,
    /// <summary>A value was encrypted into the CyType.</summary>
    Encrypted,
    /// <summary>A general operation was performed on the instance.</summary>
    OperationPerformed,
    /// <summary>The encryption key was rotated.</summary>
    KeyRotated,
    /// <summary>The instance was marked as compromised.</summary>
    Compromised,
    /// <summary>The instance was marked as tainted.</summary>
    Tainted,
    /// <summary>The taint flag was cleared from the instance.</summary>
    TaintCleared,
    /// <summary>The instance was automatically destroyed after reaching its decryption limit.</summary>
    AutoDestroyed,
    /// <summary>The instance was transferred to a different security context.</summary>
    Transferred,
    /// <summary>The security policy governing the instance was changed.</summary>
    PolicyChanged,
    /// <summary>The instance was disposed and its sensitive memory zeroed.</summary>
    Disposed
}
