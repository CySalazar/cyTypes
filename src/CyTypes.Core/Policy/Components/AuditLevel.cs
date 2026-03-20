namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Specifies the verbosity level for security audit logging.
/// </summary>
public enum AuditLevel
{
    /// <summary>Log every operation performed on the encrypted value.</summary>
    AllOperations,

    /// <summary>Log only decryption and data transfer operations.</summary>
    DecryptionsAndTransfers,

    /// <summary>Log only detected compromise or policy violation events.</summary>
    CompromiseOnly,

    /// <summary>Disable audit logging entirely.</summary>
    None
}
