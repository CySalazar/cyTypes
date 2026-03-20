using CyTypes.Core.Security;
using Microsoft.Extensions.Logging;

namespace CyTypes.Logging;

/// <summary>
/// An <see cref="IAuditSink"/> implementation that forwards security audit events to an <see cref="ILogger"/>.
/// </summary>
public sealed class LoggingAuditSink : IAuditSink
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoggingAuditSink"/> class.
    /// </summary>
    /// <param name="logger">The logger to write audit events to.</param>
    public LoggingAuditSink(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public void Receive(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        var logLevel = securityEvent.EventType switch
        {
            SecurityEventType.Compromised => LogLevel.Critical,
            SecurityEventType.AutoDestroyed => LogLevel.Warning,
            SecurityEventType.KeyRotated => LogLevel.Information,
            SecurityEventType.Decrypted => LogLevel.Debug,
            SecurityEventType.Tainted => LogLevel.Warning,
            _ => LogLevel.Information
        };

        _logger.Log(logLevel,
            "CyTypes Audit: {EventType} | Instance={InstanceId} | Policy={PolicyName} | {Description}",
            securityEvent.EventType,
            securityEvent.InstanceId,
            securityEvent.PolicyName,
            securityEvent.Description);
    }
}
