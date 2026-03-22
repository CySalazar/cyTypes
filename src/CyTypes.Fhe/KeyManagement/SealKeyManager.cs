using CyTypes.Core.Policy.Components;
using Microsoft.Research.SEAL;

namespace CyTypes.Fhe.KeyManagement;

/// <summary>
/// Manages SEAL context, key generation, and serialization for FHE operations.
/// Supports both BFV and CKKS schemes. Thread-safe via locking.
/// </summary>
public sealed class SealKeyManager : IDisposable
{
    private readonly object _lock = new();
    private SEALContext? _context;
    private KeyGenerator? _keyGen;
    private Microsoft.Research.SEAL.PublicKey? _publicKey;
    private SecretKey? _secretKey;
    private RelinKeys? _relinKeys;
    private Microsoft.Research.SEAL.GaloisKeys? _galoisKeys;
    private bool _disposed;
    private bool _initialized;
    private FheScheme _scheme;

    /// <summary>Gets the SEAL context, or null if not initialized.</summary>
    public SEALContext? Context
    {
        get { lock (_lock) { return _context; } }
    }

    /// <summary>Gets the public key, or null if not initialized.</summary>
    public Microsoft.Research.SEAL.PublicKey? PublicKey
    {
        get { lock (_lock) { return _publicKey; } }
    }

    /// <summary>Gets the secret key, or null if not initialized.</summary>
    public SecretKey? SecretKey
    {
        get { lock (_lock) { return _secretKey; } }
    }

    /// <summary>Gets the relinearization keys, or null if not initialized.</summary>
    public RelinKeys? RelinKeys
    {
        get { lock (_lock) { return _relinKeys; } }
    }

    /// <summary>Gets the Galois keys (for CKKS rotation operations), or null if not initialized or BFV.</summary>
    public Microsoft.Research.SEAL.GaloisKeys? GaloisKeys
    {
        get { lock (_lock) { return _galoisKeys; } }
    }

    /// <summary>Gets whether this manager has been initialized.</summary>
    public bool IsInitialized
    {
        get { lock (_lock) { return _initialized; } }
    }

    /// <summary>Gets the FHE scheme used by this manager.</summary>
    public FheScheme Scheme
    {
        get { lock (_lock) { return _scheme; } }
    }

    /// <summary>
    /// Initializes the SEAL context and generates keys for the specified scheme and parameters.
    /// </summary>
    public void Initialize(FheScheme scheme, EncryptionParameters parms)
    {
        ArgumentNullException.ThrowIfNull(parms);

        lock (_lock)
        {
            if (_initialized)
                throw new InvalidOperationException("SealKeyManager is already initialized.");

            _context = new SEALContext(parms);
            _keyGen = new KeyGenerator(_context);
            _scheme = scheme;

            _keyGen.CreatePublicKey(out var pk);
            _publicKey = pk;
            _secretKey = _keyGen.SecretKey;
            _keyGen.CreateRelinKeys(out var rk);
            _relinKeys = rk;

            // CKKS needs GaloisKeys for rotation operations
            if (scheme == FheScheme.CKKS)
            {
                _keyGen.CreateGaloisKeys(out var gk);
                _galoisKeys = gk;
            }

            _initialized = true;
        }
    }

    /// <summary>
    /// Serializes all keys to a <see cref="SealKeyBundle"/> for storage.
    /// </summary>
    public SealKeyBundle ExportKeyBundle()
    {
        lock (_lock)
        {
            if (!_initialized || _context == null || _publicKey == null || _secretKey == null || _relinKeys == null)
                throw new InvalidOperationException("SealKeyManager is not initialized.");

            using var pkStream = new MemoryStream();
            _publicKey.Save(pkStream);

            using var skStream = new MemoryStream();
            _secretKey.Save(skStream);

            using var rkStream = new MemoryStream();
            _relinKeys.Save(rkStream);

            byte[]? gkData = null;
            if (_galoisKeys != null)
            {
                using var gkStream = new MemoryStream();
                _galoisKeys.Save(gkStream);
                gkData = gkStream.ToArray();
            }

            return new SealKeyBundle(pkStream.ToArray(), skStream.ToArray(), rkStream.ToArray(), gkData);
        }
    }

    /// <summary>Disposes all SEAL resources and zeros key material.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;

            _galoisKeys?.Dispose();
            _relinKeys?.Dispose();
            _publicKey?.Dispose();
            _secretKey?.Dispose();
            _keyGen?.Dispose();
            _context?.Dispose();

            _galoisKeys = null;
            _relinKeys = null;
            _publicKey = null;
            _secretKey = null;
            _keyGen = null;
            _context = null;
            _initialized = false;
        }
    }
}
