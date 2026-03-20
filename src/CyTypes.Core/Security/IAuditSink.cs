namespace CyTypes.Core.Security;

/// <summary>
/// Receives security audit events for external processing (logging, SIEM, database, etc.).
/// Implementations must be thread-safe.
/// </summary>
public interface IAuditSink
{
    /// <summary>
    /// Called for each security event that passes the audit level filter.
    /// </summary>
    void Receive(SecurityEvent securityEvent);
}
