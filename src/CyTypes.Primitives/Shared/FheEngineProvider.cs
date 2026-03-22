using System.Collections.Concurrent;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy.Components;

namespace CyTypes.Primitives.Shared;

/// <summary>
/// Multi-engine registry for FHE engines. Supports BFV (integer), CKKS (floating-point),
/// comparison, and deterministic encryption engines. Configured at startup via DI.
/// </summary>
public static class FheEngineProvider
{
    private static readonly ConcurrentDictionary<string, object> _engines = new();

    private const string BfvKey = "BFV";
    private const string CkksKey = "CKKS";
    private const string ComparisonKey = "Comparison";
    private const string DeterministicKey = "Deterministic";

    /// <summary>Configures the BFV integer FHE engine.</summary>
    public static void Configure(IFheEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);
        _engines[BfvKey] = engine;
    }

    /// <summary>Configures the CKKS floating-point FHE engine.</summary>
    public static void Configure(IFheFloatingPointEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);
        _engines[CkksKey] = engine;
    }

    /// <summary>Configures the homomorphic comparison engine.</summary>
    public static void Configure(IFheComparisonEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);
        _engines[ComparisonKey] = engine;
    }

    /// <summary>Configures the deterministic encryption engine for string equality.</summary>
    public static void Configure(IDeterministicEncryptionEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);
        _engines[DeterministicKey] = engine;
    }

    /// <summary>Gets the currently configured BFV integer engine, or null if not configured. Backward compatible.</summary>
    public static IFheEngine? Current => GetIntegerEngine();

    /// <summary>Gets the BFV integer FHE engine.</summary>
    public static IFheEngine? GetIntegerEngine()
        => _engines.TryGetValue(BfvKey, out var e) ? (IFheEngine)e : null;

    /// <summary>Gets the CKKS floating-point FHE engine.</summary>
    public static IFheFloatingPointEngine? GetFloatingPointEngine()
        => _engines.TryGetValue(CkksKey, out var e) ? (IFheFloatingPointEngine)e : null;

    /// <summary>Gets the homomorphic comparison engine.</summary>
    public static IFheComparisonEngine? GetComparisonEngine()
        => _engines.TryGetValue(ComparisonKey, out var e) ? (IFheComparisonEngine)e : null;

    /// <summary>Gets the deterministic encryption engine.</summary>
    public static IDeterministicEncryptionEngine? GetDeterministicEngine()
        => _engines.TryGetValue(DeterministicKey, out var e) ? (IDeterministicEncryptionEngine)e : null;

    /// <summary>Resets all registered engines (for testing and cleanup).</summary>
    public static void Reset() => _engines.Clear();
}
