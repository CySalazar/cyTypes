using System.Collections.Concurrent;
using CyTypes.Core.Policy.Components;
using Microsoft.Extensions.Logging;

namespace CyTypes.Core.Security;

/// <summary>Records and dispatches security events, maintaining a bounded ring buffer of recent events.</summary>
public sealed class SecurityAuditor
{
    private readonly ILogger<SecurityAuditor> _logger;
    private readonly ConcurrentQueue<SecurityEvent> _recentEvents = new();
    private readonly IReadOnlyList<IAuditSink> _sinks;
    private const int MaxRecentEvents = 1000;

    /// <summary>Initializes a new <see cref="SecurityAuditor"/> with no external audit sinks.</summary>
    public SecurityAuditor(ILogger<SecurityAuditor> logger)
        : this(logger, Array.Empty<IAuditSink>())
    {
    }

    /// <summary>Initializes a new <see cref="SecurityAuditor"/> with the specified audit sinks.</summary>
    public SecurityAuditor(ILogger<SecurityAuditor> logger, IEnumerable<IAuditSink> sinks)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        ArgumentNullException.ThrowIfNull(sinks);
        _sinks = sinks.ToArray();
    }

    /// <summary>Records a security event if it passes the specified audit level filter.</summary>
    public void RecordEvent(SecurityEvent securityEvent, AuditLevel auditLevel)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        if (!ShouldRecord(securityEvent.EventType, auditLevel))
            return;

        _recentEvents.Enqueue(securityEvent);

        // Trim ring buffer
        while (_recentEvents.Count > MaxRecentEvents)
            _recentEvents.TryDequeue(out _);

        LogEvent(securityEvent);
        DispatchToSinks(securityEvent);
    }

    /// <summary>Returns a snapshot of recently recorded security events.</summary>
    public IReadOnlyList<SecurityEvent> GetRecentEvents()
    {
        return _recentEvents.ToArray();
    }

    private static bool ShouldRecord(SecurityEventType eventType, AuditLevel level) => level switch
    {
        AuditLevel.AllOperations => true,
        AuditLevel.DecryptionsAndTransfers => eventType is
            SecurityEventType.Decrypted or
            SecurityEventType.Transferred or
            SecurityEventType.Compromised or
            SecurityEventType.AutoDestroyed or
            SecurityEventType.KeyRotated,
        AuditLevel.CompromiseOnly => eventType is
            SecurityEventType.Compromised or
            SecurityEventType.AutoDestroyed,
        AuditLevel.None => false,
        _ => false
    };

    private void LogEvent(SecurityEvent evt)
    {
        var logLevel = evt.EventType switch
        {
            SecurityEventType.Compromised => LogLevel.Critical,
            SecurityEventType.AutoDestroyed => LogLevel.Warning,
            _ => LogLevel.Information
        };

        _logger.Log(logLevel,
            "CyTypes Security Event: {EventType} | Instance: {InstanceId} | Policy: {PolicyName} | {Description}",
            evt.EventType, evt.InstanceId, evt.PolicyName, evt.Description);
    }

    private void DispatchToSinks(SecurityEvent evt)
    {
        foreach (var sink in _sinks)
        {
            try
            {
                sink.Receive(evt);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Audit sink {SinkType} failed to receive event {EventType}",
                    sink.GetType().Name, evt.EventType);
            }
        }
    }
}
