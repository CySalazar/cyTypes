using System.Security.Cryptography;

namespace CyTypes.Fhe.KeyManagement;

/// <summary>
/// Holds serialized SEAL key material (public, secret, relinearization keys).
/// </summary>
public sealed class SealKeyBundle : IDisposable
{
    /// <summary>Gets the serialized public key.</summary>
    public byte[] PublicKey { get; }

    /// <summary>Gets the serialized secret key.</summary>
    public byte[] SecretKey { get; }

    /// <summary>Gets the serialized relinearization keys.</summary>
    public byte[] RelinKeys { get; }

    /// <summary>Gets the serialized Galois keys (for CKKS rotation operations), or null if BFV-only.</summary>
    public byte[]? GaloisKeys { get; }

    private bool _disposed;

    /// <summary>Initializes a new key bundle with the specified serialized keys.</summary>
    public SealKeyBundle(byte[] publicKey, byte[] secretKey, byte[] relinKeys, byte[]? galoisKeys = null)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        SecretKey = secretKey ?? throw new ArgumentNullException(nameof(secretKey));
        RelinKeys = relinKeys ?? throw new ArgumentNullException(nameof(relinKeys));
        GaloisKeys = galoisKeys;
    }

    /// <summary>Releases key material if Dispose was not called.</summary>
    ~SealKeyBundle()
    {
        Dispose();
    }

    /// <summary>Securely zeros and disposes all key material.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(SecretKey);
        CryptographicOperations.ZeroMemory(PublicKey);
        CryptographicOperations.ZeroMemory(RelinKeys);
        if (GaloisKeys != null)
            CryptographicOperations.ZeroMemory(GaloisKeys);
        GC.SuppressFinalize(this);
    }
}
