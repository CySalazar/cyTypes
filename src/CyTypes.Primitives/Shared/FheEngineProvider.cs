using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Primitives.Shared;

/// <summary>
/// Static service locator for the FHE engine. Configured at startup via DI.
/// Avoids modifying CyTypeBase constructor signatures.
/// </summary>
public static class FheEngineProvider
{
    private static IFheEngine? _engine;

    /// <summary>Configures the global FHE engine instance.</summary>
    public static void Configure(IFheEngine engine) => _engine = engine;

    /// <summary>Gets the currently configured FHE engine, or null if not configured.</summary>
    public static IFheEngine? Current => _engine;

    /// <summary>Resets the provider (for testing only).</summary>
    internal static void Reset() => _engine = null;
}
