using CyTypes.Primitives.Shared;
using Microsoft.Extensions.Logging;

namespace CyTypes.Logging;

/// <summary>
/// An <see cref="ILogger"/> decorator that redacts CyType values from log messages.
/// </summary>
public sealed partial class RedactingLogger : ILogger
{
    private readonly ILogger _inner;
    private const string RedactedPlaceholder = "[REDACTED:CyType]";

    /// <summary>
    /// Initializes a new instance of the <see cref="RedactingLogger"/> class.
    /// </summary>
    /// <param name="inner">The inner logger to delegate to after redaction.</param>
    public RedactingLogger(ILogger inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc/>
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return _inner.BeginScope(state);
    }

    /// <inheritdoc/>
    public bool IsEnabled(LogLevel logLevel) => _inner.IsEnabled(logLevel);

    /// <inheritdoc/>
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;

        // Wrap the formatter to redact CyType values from the message
        _inner.Log(logLevel, eventId, state, exception, (s, ex) =>
        {
            var message = formatter(s, ex);
            return RedactCyTypes(message);
        });
    }

    /// <summary>Redacts CyType metadata, hex payloads, and base64 blobs from the given message.</summary>
    public static string RedactCyTypes(string message)
    {
        // CyTypeBase.ToString() already returns "[TypeName:Encrypted|...]" which is safe.
        // This is an additional safety net for cases where ToString() might be bypassed
        // or where values are interpolated before reaching the logger.

        if (string.IsNullOrEmpty(message))
            return message;

        // Redact any CyType metadata patterns that might leak internal state
        var result = CyTypeMetadataPattern().Replace(message, RedactedPlaceholder);

        // Redact hex-encoded byte sequences (potential encrypted payload leaks: 64+ hex chars)
        result = HexPayloadPattern().Replace(result, RedactedPlaceholder);

        // Redact base64-encoded blobs (48+ chars, potential ciphertext leaks)
        result = Base64PayloadPattern().Replace(result, RedactedPlaceholder);

        return result;
    }

    [System.Text.RegularExpressions.GeneratedRegex(
        @"\[Cy\w+:Encrypted\|[^\]]*\]",
        System.Text.RegularExpressions.RegexOptions.Compiled)]
    private static partial System.Text.RegularExpressions.Regex CyTypeMetadataPattern();

    [System.Text.RegularExpressions.GeneratedRegex(
        @"(?<![A-Za-z0-9])[0-9a-fA-F]{64,2048}(?![A-Za-z0-9])",
        System.Text.RegularExpressions.RegexOptions.Compiled)]
    private static partial System.Text.RegularExpressions.Regex HexPayloadPattern();

    [System.Text.RegularExpressions.GeneratedRegex(
        @"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,2048}={0,2}(?![A-Za-z0-9+/=])",
        System.Text.RegularExpressions.RegexOptions.Compiled)]
    private static partial System.Text.RegularExpressions.Regex Base64PayloadPattern();
}

/// <summary>
/// An <see cref="ILoggerProvider"/> that wraps another provider and returns <see cref="RedactingLogger"/> instances.
/// </summary>
public sealed class RedactingLoggerProvider : ILoggerProvider
{
    private readonly ILoggerProvider _inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="RedactingLoggerProvider"/> class.
    /// </summary>
    /// <param name="inner">The underlying logger provider to wrap.</param>
    public RedactingLoggerProvider(ILoggerProvider inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    /// <inheritdoc/>
    public ILogger CreateLogger(string categoryName)
    {
        return new RedactingLogger(_inner.CreateLogger(categoryName));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _inner.Dispose();
    }
}
