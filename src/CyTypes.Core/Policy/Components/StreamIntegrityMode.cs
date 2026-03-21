namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Defines how stream integrity is verified.
/// </summary>
public enum StreamIntegrityMode
{
    /// <summary>Each chunk is verified via GCM tag, and the entire stream is verified via HMAC-SHA512 footer.</summary>
    PerChunkPlusFooter,
    /// <summary>Each chunk is verified via GCM tag only; no footer HMAC.</summary>
    PerChunkOnly
}
