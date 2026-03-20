using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Fhe.NoiseBudget;
using Microsoft.Research.SEAL;

namespace CyTypes.Fhe.Crypto;

/// <summary>
/// BFV-based FHE engine implementing <see cref="IFheEngine"/> using Microsoft SEAL.
/// Supports exact integer arithmetic on encrypted data.
/// </summary>
public sealed class SealBfvEngine : IFheEngine, IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly Encryptor _encryptor;
    private readonly Decryptor _decryptor;
    private readonly Evaluator _evaluator;
    private readonly BatchEncoder _encoder;
    private bool _disposed;

    /// <inheritdoc/>
    public FheScheme Scheme => FheScheme.BFV;

    /// <summary>Gets the SEAL context from the key manager.</summary>
    internal SEALContext Context => _keyManager.Context!;

    /// <summary>
    /// Initializes the BFV engine from an already-initialized <see cref="SealKeyManager"/>.
    /// </summary>
    public SealBfvEngine(SealKeyManager keyManager)
    {
        _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));

        if (!keyManager.IsInitialized)
            throw new InvalidOperationException("SealKeyManager must be initialized before creating SealBfvEngine.");

        var ctx = keyManager.Context!;
        _encryptor = new Encryptor(ctx, keyManager.PublicKey!);
        _decryptor = new Decryptor(ctx, keyManager.SecretKey!);
        _evaluator = new Evaluator(ctx);
        _encoder = new BatchEncoder(ctx);
    }

    /// <inheritdoc/>
    public byte[] Encrypt(long value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var plain = EncodeLong(value);
        using var encrypted = new Ciphertext();
        _encryptor.Encrypt(plain, encrypted);
        return SealCiphertextSerializer.Serialize(encrypted, SealCiphertextSerializer.SchemeBfv);
    }

    /// <inheritdoc/>
    public long Decrypt(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ciphertext);

        using var ct = SealCiphertextSerializer.Deserialize(ciphertext, Context);
        using var plain = new Plaintext();
        _decryptor.Decrypt(ct, plain);
        return DecodeLong(plain);
    }

    /// <inheritdoc/>
    public byte[] Add(byte[] a, byte[] b)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        using var ctA = SealCiphertextSerializer.Deserialize(a, Context);
        using var ctB = SealCiphertextSerializer.Deserialize(b, Context);
        using var result = new Ciphertext();
        _evaluator.Add(ctA, ctB, result);
        return SealCiphertextSerializer.Serialize(result, SealCiphertextSerializer.SchemeBfv);
    }

    /// <inheritdoc/>
    public byte[] Subtract(byte[] a, byte[] b)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        using var ctA = SealCiphertextSerializer.Deserialize(a, Context);
        using var ctB = SealCiphertextSerializer.Deserialize(b, Context);
        using var result = new Ciphertext();
        _evaluator.Sub(ctA, ctB, result);
        return SealCiphertextSerializer.Serialize(result, SealCiphertextSerializer.SchemeBfv);
    }

    /// <inheritdoc/>
    public byte[] Multiply(byte[] a, byte[] b)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        using var ctA = SealCiphertextSerializer.Deserialize(a, Context);
        using var ctB = SealCiphertextSerializer.Deserialize(b, Context);
        using var result = new Ciphertext();
        _evaluator.Multiply(ctA, ctB, result);

        // Relinearize after multiplication to control ciphertext size growth
        using var relinResult = new Ciphertext();
        _evaluator.Relinearize(result, _keyManager.RelinKeys!, relinResult);

        return SealCiphertextSerializer.Serialize(relinResult, SealCiphertextSerializer.SchemeBfv);
    }

    /// <inheritdoc/>
    public byte[] Negate(byte[] a)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);

        using var ct = SealCiphertextSerializer.Deserialize(a, Context);
        using var result = new Ciphertext();
        _evaluator.Negate(ct, result);
        return SealCiphertextSerializer.Serialize(result, SealCiphertextSerializer.SchemeBfv);
    }

    /// <inheritdoc/>
    public int GetNoiseBudget(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ciphertext);

        using var ct = SealCiphertextSerializer.Deserialize(ciphertext, Context);
        return _decryptor.InvariantNoiseBudget(ct);
    }

    private Plaintext EncodeLong(long value)
    {
        var slotCount = _encoder.SlotCount;
        var values = new long[slotCount];
        values[0] = value;
        var plain = new Plaintext();
        _encoder.Encode(values, plain);
        return plain;
    }

    private long DecodeLong(Plaintext plain)
    {
        var values = new List<long>((int)_encoder.SlotCount);
        _encoder.Decode(plain, values);
        return values[0];
    }

    /// <summary>Disposes SEAL encryptor, decryptor, evaluator, and encoder.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _encoder.Dispose();
        _evaluator.Dispose();
        _decryptor.Dispose();
        _encryptor.Dispose();
    }
}
