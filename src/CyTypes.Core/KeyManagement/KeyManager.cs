using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Memory;

namespace CyTypes.Core.KeyManagement;

/// <summary>
/// Manages the lifecycle of a 256-bit symmetric encryption key, including rotation and TTL enforcement.
/// </summary>
public sealed class KeyManager : IKeyManager
{
    private SecureBuffer _keyBuffer;
    private int _isDisposed;
    private int _usageCount;
    private readonly object _lock = new();
    private readonly TimeSpan? _ttl;
    private DateTime _createdUtc;

    /// <summary>
    /// Gets the unique identifier of the current key.
    /// </summary>
    public Guid KeyId { get; private set; }

    /// <summary>
    /// Gets the number of times this key has been used.
    /// </summary>
    public int UsageCount => _usageCount;

    /// <summary>
    /// Gets the UTC timestamp when the current key was created.
    /// </summary>
    public DateTime KeyCreatedUtc => _createdUtc;

    /// <summary>
    /// Gets the optional time-to-live for the key, after which it is considered expired.
    /// </summary>
    public TimeSpan? Ttl => _ttl;

    /// <summary>
    /// Gets the current key bytes. Throws if the key is disposed or expired.
    /// </summary>
    public ReadOnlySpan<byte> CurrentKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) != 0, this);
            CheckTtl();
            return _keyBuffer.AsReadOnlySpan();
        }
    }

    /// <summary>
    /// Initializes a new <see cref="KeyManager"/> with a randomly generated 256-bit key.
    /// </summary>
    public KeyManager()
    {
        _keyBuffer = new SecureBuffer(32);
        RandomNumberGenerator.Fill(_keyBuffer.AsSpan());
        KeyId = Guid.NewGuid();
        _createdUtc = DateTime.UtcNow;
    }

    /// <summary>
    /// Initializes a new <see cref="KeyManager"/> with the specified 32-byte key.
    /// </summary>
    /// <param name="initialKey">A 32-byte (256-bit) key.</param>
    public KeyManager(ReadOnlySpan<byte> initialKey)
    {
        if (initialKey.Length != 32)
            throw new ArgumentException("Key must be 32 bytes (256 bits).", nameof(initialKey));

        _keyBuffer = new SecureBuffer(32);
        _keyBuffer.Write(initialKey);
        KeyId = Guid.NewGuid();
        _createdUtc = DateTime.UtcNow;
    }

    /// <summary>
    /// Initializes a new <see cref="KeyManager"/> with the specified key and time-to-live.
    /// </summary>
    /// <param name="initialKey">A 32-byte (256-bit) key.</param>
    /// <param name="ttl">The time-to-live for the key.</param>
    public KeyManager(ReadOnlySpan<byte> initialKey, TimeSpan ttl) : this(initialKey)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);
        _ttl = ttl;
    }

    /// <summary>
    /// Initializes a new <see cref="KeyManager"/> with a random key and time-to-live.
    /// </summary>
    /// <param name="ttl">The time-to-live for the key.</param>
    public KeyManager(TimeSpan ttl) : this()
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);
        _ttl = ttl;
    }

    /// <summary>
    /// Gets a value indicating whether the key has exceeded its TTL.
    /// </summary>
    public bool IsExpired => _ttl.HasValue && (DateTime.UtcNow - _createdUtc) > _ttl.Value;

    /// <summary>
    /// Derives a new encryption key from the current key mixed with fresh entropy (HKDF).
    /// <para>
    /// <b>Important:</b> After calling this method, any ciphertext encrypted with the previous key
    /// is no longer decryptable. Use <c>CyTypeBase.RotateKeyAndReEncrypt()</c> which atomically
    /// decrypts, rotates, and re-encrypts to avoid data loss.
    /// </para>
    /// </summary>
    public void RotateKey()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) != 0, this);

        lock (_lock)
        {
            Span<byte> entropy = stackalloc byte[32];
            RandomNumberGenerator.Fill(entropy);

            Span<byte> combined = stackalloc byte[64];
            _keyBuffer.AsReadOnlySpan().CopyTo(combined);
            entropy.CopyTo(combined[32..]);

            byte[]? newKeyBytes = null;
            try
            {
                newKeyBytes = HkdfKeyDerivation.DeriveKey(
                    combined,
                    outputLength: 32,
                    info: "CyTypes.KeyRotation"u8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(combined);
                CryptographicOperations.ZeroMemory(entropy);
            }

            var newBuffer = new SecureBuffer(32);
            try
            {
                newBuffer.Write(newKeyBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(newKeyBytes);
            }

            var oldBuffer = _keyBuffer;
            _keyBuffer = newBuffer;
            oldBuffer.Dispose();

            KeyId = Guid.NewGuid();
            _usageCount = 0;
            _createdUtc = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Atomically increments the usage counter for this key.
    /// </summary>
    public void IncrementUsage()
    {
        Interlocked.Increment(ref _usageCount);
    }

    /// <summary>
    /// Creates a new <see cref="KeyManager"/> with a copy of the current key material.
    /// The cloned manager has its own independent key buffer and lifecycle.
    /// </summary>
    public KeyManager Clone()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) != 0, this);
        CheckTtl();
        return new KeyManager(_keyBuffer.AsReadOnlySpan());
    }

    private void CheckTtl()
    {
        if (_ttl.HasValue)
        {
            var age = DateTime.UtcNow - _createdUtc;
            if (age > _ttl.Value)
                throw new KeyExpiredException(KeyId, age, _ttl.Value);
        }
    }

    /// <summary>
    /// Disposes the key buffer, securely zeroing key material.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;
        _keyBuffer.Dispose();
    }
}
