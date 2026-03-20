using System.Security.Cryptography;

namespace CyTypes.Core.Crypto.Pqc;

/// <summary>
/// Holds an ML-KEM (Kyber) key pair with secure disposal.
/// </summary>
public sealed class MlKemKeyPair : IDisposable
{
    /// <summary>Gets the public key bytes.</summary>
    public byte[] PublicKey { get; }

    /// <summary>Gets the secret key bytes.</summary>
    public byte[] SecretKey { get; }

    private bool _disposed;

    /// <summary>Initializes a new ML-KEM key pair.</summary>
    public MlKemKeyPair(byte[] publicKey, byte[] secretKey)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        SecretKey = secretKey ?? throw new ArgumentNullException(nameof(secretKey));
    }

    /// <summary>Securely zeros and disposes the key material.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(SecretKey);
        CryptographicOperations.ZeroMemory(PublicKey);
    }
}
