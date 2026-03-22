using System.Security.Cryptography;
using System.Text;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.KeyManagement;
using CyTypes.Core.Memory;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Core.Security;

namespace CyTypes.Primitives.Shared;

/// <summary>Abstract base class for all encrypted CyType primitives.</summary>
public abstract class CyTypeBase<TSelf, TNative> : ICyType, IFormattable
    where TSelf : CyTypeBase<TSelf, TNative>
{
    private SecureBuffer? _encryptedData;
    private readonly KeyManager _keyManager;
    private readonly ICryptoEngine _cryptoEngine;
    private bool _isDisposed;
    private readonly bool _isFheMode;

    /// <summary>Gets the security context tracking compromise and taint state.</summary>
    protected SecurityContext Security { get; }
    /// <summary>Gets the security policy governing this instance.</summary>
    public SecurityPolicy Policy { get; private set; }
    /// <summary>Gets the unique identifier for this instance.</summary>
    public Guid InstanceId { get; }
    /// <summary>Gets the UTC timestamp when this instance was created.</summary>
    public DateTime CreatedUtc { get; }
    /// <summary>Gets a value indicating whether this instance has been disposed.</summary>
    public bool IsDisposed => _isDisposed;
    /// <summary>Gets a value indicating whether this instance has been compromised.</summary>
    public bool IsCompromised => Security.IsCompromised;
    /// <summary>Gets a value indicating whether this instance has been tainted.</summary>
    public bool IsTainted => Security.IsTainted;

    /// <summary>Raised when this instance is marked as compromised.</summary>
    public event EventHandler<SecurityEvent>? SecurityBreached;
    /// <summary>Raised when the security policy is changed.</summary>
    public event EventHandler<SecurityEvent>? PolicyChanged;
    /// <summary>Raised when the taint flag is cleared.</summary>
    public event EventHandler<SecurityEvent>? TaintCleared;

    /// <summary>Initializes a new instance by encrypting the specified value.</summary>
    protected CyTypeBase(TNative value, SecurityPolicy? policy = null, ICryptoEngine? cryptoEngine = null)
    {
        Policy = policy ?? SecurityPolicy.Default;
        InstanceId = Guid.NewGuid();
        CreatedUtc = DateTime.UtcNow;
        _cryptoEngine = cryptoEngine ?? new AesGcmEngine();
        _keyManager = new KeyManager();
        _isFheMode = Policy.Arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull;
        Security = new SecurityContext(InstanceId, Policy.MaxDecryptionCount, Policy.DecryptionRateLimit);

        Security.AutoDestroyTriggered += OnAutoDestroy;
        Security.TaintCleared += OnTaintCleared;

        EncryptValue(value);
    }

    /// <summary>Initializes a new instance from pre-existing FHE ciphertext bytes.</summary>
    protected CyTypeBase(byte[] fheCiphertext, SecurityPolicy policy, FheCiphertextTag tag)
    {
        ArgumentNullException.ThrowIfNull(fheCiphertext);
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        InstanceId = Guid.NewGuid();
        CreatedUtc = DateTime.UtcNow;
        _cryptoEngine = new AesGcmEngine();
        _keyManager = new KeyManager();
        _isFheMode = true;
        Security = new SecurityContext(InstanceId, Policy.MaxDecryptionCount, Policy.DecryptionRateLimit);

        Security.AutoDestroyTriggered += OnAutoDestroy;
        Security.TaintCleared += OnTaintCleared;

        SetEncryptedBytes(fheCiphertext);
    }

    /// <summary>Tag type to disambiguate the FHE ciphertext constructor from the value constructor.</summary>
    protected readonly struct FheCiphertextTag;

    /// <summary>
    /// Initializes a new instance by copying encrypted data and key material without decryption.
    /// Used by <see cref="Clone"/> to create a copy without exposing plaintext.
    /// </summary>
    protected CyTypeBase(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
    {
        ArgumentNullException.ThrowIfNull(encryptedBytes);
        ArgumentNullException.ThrowIfNull(clonedKeyManager);
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        InstanceId = Guid.NewGuid();
        CreatedUtc = DateTime.UtcNow;
        _cryptoEngine = new AesGcmEngine();
        _keyManager = clonedKeyManager;
        _isFheMode = policy.Arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull;
        Security = new SecurityContext(InstanceId, policy.MaxDecryptionCount, policy.DecryptionRateLimit);

        Security.AutoDestroyTriggered += OnAutoDestroy;
        Security.TaintCleared += OnTaintCleared;

        SetEncryptedBytes(encryptedBytes);
    }

    /// <summary>Encrypts the specified value and stores it in a secure buffer.</summary>
    protected void EncryptValue(TNative value)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (_isFheMode)
        {
            // CKKS path for floating-point types
            if (IsFloatingPointType)
            {
                var fpEngine = FheEngineProvider.GetFloatingPointEngine()
                    ?? throw new InvalidOperationException("CKKS FHE engine not configured. Register via AddCyTypesCkks().");
                var doubleVal = ConvertToDouble(value);
                var ciphertext = fpEngine.Encrypt(doubleVal);
                SetEncryptedBytes(ciphertext);
                return;
            }

            // BFV path for integer types
            var fheEngine = FheEngineProvider.Current
                ?? throw new InvalidOperationException("FHE engine not configured. Register via AddCyTypesFhe().");
            var plainBytes = SerializeValue(value);
            try
            {
                long longVal = ConvertToLong(plainBytes);
                var ciphertext = fheEngine.Encrypt(longVal);
                SetEncryptedBytes(ciphertext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plainBytes);
            }
            return;
        }

        var plaintext = SerializeValue(value);
        try
        {
            var ciphertext = _cryptoEngine.Encrypt(plaintext, _keyManager.CurrentKey);
            var newBuffer = new SecureBuffer(ciphertext.Length);
            newBuffer.Write(ciphertext);

            var old = _encryptedData;
            _encryptedData = newBuffer;
            old?.Dispose();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Decrypts and returns the stored value, incrementing the decryption counter.</summary>
    protected TNative DecryptValue()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (_encryptedData == null)
            throw new InvalidOperationException("No encrypted data available.");

        if (_isFheMode)
        {
            // CKKS path for floating-point types
            if (IsFloatingPointType)
            {
                var fpEngine = FheEngineProvider.GetFloatingPointEngine()
                    ?? throw new InvalidOperationException("CKKS FHE engine not configured. Register via AddCyTypesCkks().");
                var cipherBytes = _encryptedData.ToArray();
                try
                {
                    double doubleVal = fpEngine.Decrypt(cipherBytes);
                    return ConvertFromDouble(doubleVal);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(cipherBytes);
                    Security.IncrementDecryption();
                }
            }

            // BFV path for integer types
            var fheEngine = FheEngineProvider.Current
                ?? throw new InvalidOperationException("FHE engine not configured. Register via AddCyTypesFhe().");
            var bfvCipherBytes = _encryptedData.ToArray();
            try
            {
                long longVal = fheEngine.Decrypt(bfvCipherBytes);
                var resultBytes = ConvertFromLong(longVal);
                try
                {
                    return DeserializeValue(resultBytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(resultBytes);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bfvCipherBytes);
                Security.IncrementDecryption();
            }
        }

        var ciphertext = _encryptedData.ToArray();
        byte[]? plaintext = null;
        try
        {
            plaintext = _cryptoEngine.Decrypt(ciphertext, _keyManager.CurrentKey);
            return DeserializeValue(plaintext);
        }
        finally
        {
            // SECURITY: Zero both ciphertext copy and plaintext in all paths (success or exception)
            CryptographicOperations.ZeroMemory(ciphertext);
            if (plaintext != null)
                CryptographicOperations.ZeroMemory(plaintext);
            // Increment after decryption completes; may trigger auto-destroy
            Security.IncrementDecryption();
        }
    }

    /// <summary>Sets the encrypted data buffer directly from raw bytes (used for FHE ciphertexts).</summary>
    internal void SetEncryptedBytes(byte[] data)
    {
        var newBuffer = new SecureBuffer(data.Length);
        newBuffer.Write(data);
        var old = _encryptedData;
        _encryptedData = newBuffer;
        old?.Dispose();
    }

    /// <summary>Gets whether this instance uses FHE mode.</summary>
    internal bool IsFheMode => _isFheMode;

    /// <summary>Gets whether TNative is a floating-point type (float, double, decimal).</summary>
    private static bool IsFloatingPointType =>
        typeof(TNative) == typeof(float) || typeof(TNative) == typeof(double) || typeof(TNative) == typeof(decimal);

    private static long ConvertToLong(byte[] data) => data.Length switch
    {
        4 => BitConverter.ToInt32(data),
        8 => BitConverter.ToInt64(data),
        _ => throw new NotSupportedException($"Cannot convert {data.Length}-byte value to long for FHE.")
    };

    private static byte[] ConvertFromLong(long value)
    {
        // The concrete type's DeserializeValue will handle the appropriate size
        if (typeof(TNative) == typeof(int))
            return BitConverter.GetBytes((int)value);
        return BitConverter.GetBytes(value);
    }

    private static double ConvertToDouble(TNative value)
    {
        if (typeof(TNative) == typeof(float))
            return (double)(float)(object)value!;
        if (typeof(TNative) == typeof(double))
            return (double)(object)value!;
        if (typeof(TNative) == typeof(decimal))
            return (double)(decimal)(object)value!;
        throw new NotSupportedException($"Cannot convert {typeof(TNative).Name} to double for CKKS FHE.");
    }

    private static TNative ConvertFromDouble(double value)
    {
        if (typeof(TNative) == typeof(float))
            return (TNative)(object)(float)value;
        if (typeof(TNative) == typeof(double))
            return (TNative)(object)value;
        if (typeof(TNative) == typeof(decimal))
            return (TNative)(object)(decimal)value;
        throw new NotSupportedException($"Cannot convert double to {typeof(TNative).Name} from CKKS FHE.");
    }

    /// <summary>Serializes the native value to a byte array for encryption.</summary>
    protected abstract byte[] SerializeValue(TNative value);
    /// <summary>Deserializes a byte array back to the native value after decryption.</summary>
    protected abstract TNative DeserializeValue(byte[] data);

    /// <summary>
    /// Atomically rotates the encryption key and re-encrypts the stored value.
    /// Decrypts with the current key, derives a new key via HKDF, then re-encrypts.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public void RotateKeyAndReEncrypt()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (_isFheMode)
            throw new NotSupportedException("Key rotation is not supported for FHE-encrypted values.");

        // Step 1: Decrypt with current key BEFORE rotation
        var value = DecryptValue();
        try
        {
            // Step 2: Rotate the key
            _keyManager.RotateKey();

            // Step 3: Re-encrypt with the new key
            EncryptValue(value);
        }
        finally
        {
            // SECURITY: value is a managed object; zero only for byte[] (best-effort)
            if (value is byte[] bytes)
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Rotates the key and re-encrypts. Alias for <see cref="RotateKeyAndReEncrypt"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public void RotateKey() => RotateKeyAndReEncrypt();

    /// <summary>
    /// Re-encrypts the stored value using the current key. Useful if you need to
    /// re-encrypt without rotating, e.g. after restoring a key from external storage.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public void ReEncryptWithCurrentKey()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        var value = DecryptValue();
        try
        {
            EncryptValue(value);
        }
        finally
        {
            if (value is byte[] bytes)
                CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal byte[] GetEncryptedBytes()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _encryptedData?.ToArray() ?? throw new InvalidOperationException("No encrypted data.");
    }

    internal ReadOnlySpan<byte> GetKey() => _keyManager.CurrentKey;

    /// <summary>
    /// Creates a deep copy of this instance without decrypting the value.
    /// The clone has a new InstanceId, fresh timestamps, and clean security flags.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public virtual TSelf Clone()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        var encBytes = GetEncryptedBytes();
        var clonedKey = _keyManager.Clone();
        return CreateClone(encBytes, Policy, clonedKey);
    }

    /// <summary>
    /// Creates a new instance from cloned encrypted bytes and key manager.
    /// Must be overridden by each concrete type to call its clone constructor.
    /// </summary>
    protected abstract TSelf CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager);

    /// <summary>
    /// Serializes the encrypted data into a secure binary envelope with HMAC-SHA512 integrity verification.
    /// The HMAC subkey is derived from the encryption key via HKDF.
    /// </summary>
    public byte[] ToSecureBytes()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        var ciphertext = GetEncryptedBytes();
        try
        {
            var encryptionKey = _keyManager.CurrentKey;
            var hmacKey = HkdfKeyDerivation.DeriveKey(
                encryptionKey,
                outputLength: 64,
                info: Encoding.UTF8.GetBytes("CyTypes.SecureSerialization.HMAC"));
            try
            {
                return SecureSerializationFormat.Serialize(ciphertext, _keyManager.KeyId, hmacKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hmacKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    /// <summary>
    /// Decrypts the value, marks this instance as compromised, and returns the plaintext.
    /// Deliberately verbose name to force developer awareness.
    /// </summary>
    public TNative ToInsecureValue()
    {
        MarkCompromised();
        return DecryptValue();
    }

    /// <summary>
    /// Elevates the policy to a higher security level. Throws if the new policy is weaker (demotion).
    /// </summary>
    public void ElevatePolicy(SecurityPolicy higher)
    {
        ArgumentNullException.ThrowIfNull(higher);
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        // SECURITY: Only allow promotion — demotion is a separate path via WithPolicy
        if (IsDemotion(Policy, higher))
        {
            throw new PolicyViolationException(
                $"ElevatePolicy does not allow demotion from {Policy.Name} to {higher.Name}. Use WithPolicy with AllowDemotion instead.");
        }

        var old = Policy;
        Policy = higher;
        PolicyChanged?.Invoke(this, new SecurityEvent(
            DateTime.UtcNow, SecurityEventType.PolicyChanged, InstanceId,
            $"Policy elevated from {old.Name} to {higher.Name}", higher.Name));
    }

    /// <summary>
    /// Creates a conceptual re-binding with a different policy.
    /// If demotion, requires AllowDemotion and marks result as tainted.
    /// </summary>
    public void ApplyPolicy(SecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (IsDemotion(Policy, policy))
        {
            if (!policy.AllowDemotion && !Policy.AllowDemotion)
            {
                throw new PolicyViolationException(
                    $"Policy demotion from {Policy.Name} to {policy.Name} is prohibited. Set AllowDemotion = true.");
            }

            Security.MarkTainted();
        }

        var old = Policy;
        Policy = policy;
        PolicyChanged?.Invoke(this, new SecurityEvent(
            DateTime.UtcNow, SecurityEventType.PolicyChanged, InstanceId,
            $"Policy changed from {old.Name} to {policy.Name}", policy.Name));
    }

    /// <summary>Marks this instance as compromised and raises the SecurityBreached event.</summary>
    public void MarkCompromised()
    {
        Security.MarkCompromised();
        SecurityBreached?.Invoke(this, new SecurityEvent(
            DateTime.UtcNow, SecurityEventType.Compromised, InstanceId,
            "Instance marked as compromised", Policy.Name));
    }

    /// <summary>Marks this instance as tainted.</summary>
    public void MarkTainted() => Security.MarkTainted();

    /// <summary>Clears the taint flag with the specified reason.</summary>
    public void ClearTaint(string reason) => Security.ClearTaint(reason);

    /// <summary>
    /// Returns true if moving from <paramref name="current"/> to <paramref name="target"/>
    /// is a security demotion (any component becomes weaker).
    /// </summary>
    private static bool IsDemotion(SecurityPolicy current, SecurityPolicy target)
    {
        // Higher ordinal = weaker security for these enums
        return (int)target.Arithmetic > (int)current.Arithmetic
            || (int)target.Comparison > (int)current.Comparison
            || (int)target.StringOperations > (int)current.StringOperations
            || (int)target.Memory > (int)current.Memory
            || (int)target.Taint > (int)current.Taint
            || (int)target.Audit > (int)current.Audit;
    }

    private void OnAutoDestroy(SecurityContext ctx)
    {
        Dispose();
    }

    private void OnTaintCleared(SecurityContext ctx, string reason)
    {
        TaintCleared?.Invoke(this, new SecurityEvent(
            DateTime.UtcNow, SecurityEventType.TaintCleared, InstanceId,
            $"Taint cleared: {reason}", Policy.Name));
    }

    /// <summary>Returns a redacted string representation that never exposes plaintext.</summary>
    public sealed override string ToString()
    {
        return $"[{typeof(TSelf).Name}:Encrypted|Policy={Policy.Name}|Compromised={IsCompromised}]";
    }

    /// <summary>
    /// Returns a formatted string representation if the policy allows it, otherwise returns a redacted string.
    /// When <see cref="SecurityPolicy.Formatting"/> is <see cref="FormattingMode.AllowFormatted"/>,
    /// the value is decrypted, formatted, and the instance is marked as compromised.
    /// </summary>
    public virtual string ToString(string? format, IFormatProvider? formatProvider)
    {
        if (Policy.Formatting == FormattingMode.AllowFormatted)
        {
            MarkCompromised();
            var value = DecryptValue();
            if (value is IFormattable formattable)
                return formattable.ToString(format, formatProvider);
            return value?.ToString() ?? string.Empty;
        }
        return ToString();
    }

    /// <summary>
    /// Writes this value's encrypted bytes to a stream writer.
    /// The value is transferred in its encrypted form — no plaintext is ever exposed.
    /// </summary>
    /// <param name="writer">The stream writer to write to.</param>
    public void WriteTo(object writer)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        // Uses dynamic dispatch to avoid CyTypes.Streams dependency in Primitives.
        // The writer must have a WriteValue<TSelf, TNative>(CyTypeBase<TSelf, TNative>) method.
        var writeMethod = writer.GetType().GetMethod("WriteValue");
        if (writeMethod == null)
            throw new ArgumentException("Writer does not have a WriteValue method.", nameof(writer));

        var genericMethod = writeMethod.MakeGenericMethod(typeof(TSelf), typeof(TNative));
        genericMethod.Invoke(writer, [this]);
    }

    /// <summary>Disposes the instance, zeroing all secure buffers and keys.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Asynchronous disposal. Returns <see cref="ValueTask.CompletedTask"/> because all
    /// underlying resources (pinned buffers, mlock) are synchronous — there is no I/O to await.
    /// This is intentional per the <c>IAsyncDisposable</c> pattern for sync-only resources.
    /// </summary>
    public ValueTask DisposeAsync()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    /// <summary>Releases managed resources. SecureBuffer handles its own finalization independently.</summary>
    protected virtual void Dispose(bool disposing)
    {
        if (_isDisposed) return;
        _isDisposed = true;

        _encryptedData?.Dispose();
        _keyManager.Dispose();
    }
}
