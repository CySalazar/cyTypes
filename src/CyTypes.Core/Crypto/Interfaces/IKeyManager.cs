namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Manages cryptographic key lifecycle including rotation and secure disposal.
/// </summary>
public interface IKeyManager : IDisposable
{
    /// <summary>
    /// Gets the current active encryption key.
    /// </summary>
    ReadOnlySpan<byte> CurrentKey { get; }

    /// <summary>
    /// Gets the unique identifier of the current key.
    /// </summary>
    Guid KeyId { get; }

    /// <summary>
    /// Gets the number of times the current key has been used.
    /// </summary>
    int UsageCount { get; }

    /// <summary>
    /// Rotates to a new key, securely discarding the previous one.
    /// </summary>
    void RotateKey();
}
