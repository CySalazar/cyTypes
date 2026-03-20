namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Specifies the level of memory protection applied to encrypted data buffers.
/// </summary>
public enum MemoryProtection
{
    /// <summary>Pins and locks memory pages and periodically re-encrypts the in-memory representation.</summary>
    PinnedLockedReEncrypting,

    /// <summary>Pins and locks memory pages to prevent swapping to disk.</summary>
    PinnedLocked,

    /// <summary>Pins memory pages only, without locking or re-encryption.</summary>
    PinnedOnly
}
