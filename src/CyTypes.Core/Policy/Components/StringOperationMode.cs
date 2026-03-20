namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Specifies how string operations are performed on encrypted string values.
/// </summary>
public enum StringOperationMode
{
    /// <summary>Uses homomorphic encryption to test string equality without decryption.</summary>
    HomomorphicEquality,

    /// <summary>Decrypts strings inside a secure enclave for operations.</summary>
    SecureEnclave
}
