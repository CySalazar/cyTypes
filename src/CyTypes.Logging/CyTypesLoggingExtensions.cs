using Microsoft.Extensions.Logging;

namespace CyTypes.Logging;

/// <summary>
/// Extension methods for integrating CyTypes log redaction into <see cref="ILoggerFactory"/>.
/// </summary>
public static class CyTypesLoggingExtensions
{
    /// <summary>
    /// Adds a redacting logger provider that scrubs CyType values from log output.
    /// </summary>
    /// <param name="factory">The logger factory to configure.</param>
    /// <param name="innerProvider">The underlying logger provider to wrap with redaction.</param>
    /// <returns>The same <paramref name="factory"/> instance for chaining.</returns>
    public static ILoggerFactory AddCyTypesRedaction(this ILoggerFactory factory, ILoggerProvider innerProvider)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(innerProvider);
        factory.AddProvider(new RedactingLoggerProvider(innerProvider));
        return factory;
    }
}
