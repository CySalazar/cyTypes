namespace CyTypes.Core.KeyManagement;

/// <summary>
/// Describes the protection level provided by a platform key store.
/// </summary>
public enum KeyStoreCapability
{
    /// <summary>
    /// Keys are protected by hardware-backed storage (e.g., Secure Enclave, TPM).
    /// </summary>
    HardwareBacked = 0,

    /// <summary>
    /// Keys are protected by the operating system (e.g., DPAPI, libsecret).
    /// </summary>
    OsProtected = 1,

    /// <summary>
    /// Keys are held in process memory only, with no OS or hardware protection.
    /// </summary>
    InMemoryOnly = 2
}
