namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Specifies how encrypted values are compared for equality or ordering.
/// </summary>
public enum ComparisonMode
{
    /// <summary>Uses a homomorphic circuit to compare values without decryption.</summary>
    HomomorphicCircuit,

    /// <summary>Compares HMAC-derived tags for equality without exposing plaintext.</summary>
    HmacBased,

    /// <summary>Decrypts values inside a secure enclave for comparison.</summary>
    SecureEnclave
}
