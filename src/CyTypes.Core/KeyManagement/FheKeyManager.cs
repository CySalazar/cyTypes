namespace CyTypes.Core.KeyManagement;

/// <summary>
/// Thin adapter for FHE key lifecycle management.
/// Actual key management is handled by SealKeyManager in CyTypes.Fhe.
/// </summary>
public sealed class FheKeyManager
{
    private bool _initialized;

    /// <summary>Gets whether the FHE key manager has been initialized.</summary>
    public bool IsInitialized => _initialized;

    /// <summary>
    /// Marks this key manager as initialized. Actual initialization is performed
    /// by the SEAL-specific key manager in CyTypes.Fhe.
    /// </summary>
    public void Initialize()
    {
        _initialized = true;
    }
}
