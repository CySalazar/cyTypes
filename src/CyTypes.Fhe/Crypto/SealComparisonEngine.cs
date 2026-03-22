using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Fhe.Crypto;

/// <summary>
/// Provides homomorphic comparison by computing encrypted differences and extracting
/// the sign at decryption time. Supports both BFV (exact) and CKKS (approximate) schemes.
/// </summary>
public sealed class SealComparisonEngine : IFheComparisonEngine
{
    private readonly IFheEngine? _integerEngine;
    private readonly IFheFloatingPointEngine? _floatingPointEngine;

    /// <summary>Creates a comparison engine for BFV integer comparisons.</summary>
    public SealComparisonEngine(IFheEngine integerEngine)
    {
        _integerEngine = integerEngine ?? throw new ArgumentNullException(nameof(integerEngine));
    }

    /// <summary>Creates a comparison engine for CKKS floating-point comparisons.</summary>
    public SealComparisonEngine(IFheFloatingPointEngine floatingPointEngine)
    {
        _floatingPointEngine = floatingPointEngine ?? throw new ArgumentNullException(nameof(floatingPointEngine));
    }

    /// <summary>Creates a comparison engine supporting both BFV and CKKS.</summary>
    public SealComparisonEngine(IFheEngine integerEngine, IFheFloatingPointEngine floatingPointEngine)
    {
        _integerEngine = integerEngine ?? throw new ArgumentNullException(nameof(integerEngine));
        _floatingPointEngine = floatingPointEngine ?? throw new ArgumentNullException(nameof(floatingPointEngine));
    }

    /// <inheritdoc/>
    public byte[] ComputeDifference(byte[] a, byte[] b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        // Detect scheme from ciphertext header
        var scheme = SealCiphertextSerializer.GetSchemeMarker(a);

        if (scheme == SealCiphertextSerializer.SchemeCkks)
        {
            var engine = _floatingPointEngine
                ?? throw new InvalidOperationException("CKKS engine not configured for floating-point comparison.");
            return engine.Subtract(a, b);
        }

        var intEngine = _integerEngine
            ?? throw new InvalidOperationException("BFV engine not configured for integer comparison.");
        return intEngine.Subtract(a, b);
    }

    /// <inheritdoc/>
    public int DecryptComparison(byte[] encryptedDifference)
    {
        ArgumentNullException.ThrowIfNull(encryptedDifference);

        var scheme = SealCiphertextSerializer.GetSchemeMarker(encryptedDifference);

        if (scheme == SealCiphertextSerializer.SchemeCkks)
        {
            var engine = _floatingPointEngine
                ?? throw new InvalidOperationException("CKKS engine not configured.");
            var diff = engine.Decrypt(encryptedDifference);
            return Math.Sign(diff);
        }

        var intEngine = _integerEngine
            ?? throw new InvalidOperationException("BFV engine not configured.");
        var intDiff = intEngine.Decrypt(encryptedDifference);
        return Math.Sign(intDiff);
    }

    /// <inheritdoc/>
    public bool DecryptEquality(byte[] encryptedDifference, double epsilon = 0.0)
    {
        ArgumentNullException.ThrowIfNull(encryptedDifference);

        var scheme = SealCiphertextSerializer.GetSchemeMarker(encryptedDifference);

        if (scheme == SealCiphertextSerializer.SchemeCkks)
        {
            var engine = _floatingPointEngine
                ?? throw new InvalidOperationException("CKKS engine not configured.");
            var diff = engine.Decrypt(encryptedDifference);
            return Math.Abs(diff) <= epsilon;
        }

        // BFV: exact comparison (epsilon = 0)
        var intEngine = _integerEngine
            ?? throw new InvalidOperationException("BFV engine not configured.");
        var intDiff = intEngine.Decrypt(encryptedDifference);
        return intDiff == 0;
    }
}
