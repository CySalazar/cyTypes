namespace CyTypes.Core.Security;

/// <summary>Immutable record representing a security-related event raised by a CyType instance.</summary>
/// <param name="Timestamp">UTC time when the event occurred.</param>
/// <param name="EventType">The category of security event.</param>
/// <param name="InstanceId">The unique identifier of the CyType instance that raised the event.</param>
/// <param name="Description">A human-readable description of the event.</param>
/// <param name="PolicyName">The name of the security policy in effect when the event occurred.</param>
public sealed record SecurityEvent(
    DateTime Timestamp,
    SecurityEventType EventType,
    Guid InstanceId,
    string Description,
    string PolicyName);
