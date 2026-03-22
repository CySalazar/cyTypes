using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.KeyManagement;
using Microsoft.Research.SEAL;

namespace CyTypes.Fhe.Crypto;

/// <summary>
/// CKKS-based FHE engine implementing <see cref="IFheFloatingPointEngine"/> using Microsoft SEAL.
/// Supports approximate floating-point arithmetic on encrypted data.
/// </summary>
public sealed class SealCkksEngine : IFheFloatingPointEngine, IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly Encryptor _encryptor;
    private readonly Decryptor _decryptor;
    private readonly Evaluator _evaluator;
    private readonly CKKSEncoder _encoder;
    private readonly double _scale;
    private bool _disposed;

    /// <inheritdoc/>
    public FheScheme Scheme => FheScheme.CKKS;

    /// <inheritdoc/>
    public double Scale => _scale;

    /// <summary>Gets the SEAL context from the key manager.</summary>
    internal SEALContext Context => _keyManager.Context!;

    /// <summary>
    /// Initializes the CKKS engine from an already-initialized <see cref="SealKeyManager"/>.
    /// </summary>
    /// <param name="keyManager">An initialized key manager with CKKS scheme.</param>
    /// <param name="scale">The encoding scale. Default is 2^40.</param>
    public SealCkksEngine(SealKeyManager keyManager, double scale = 0)
    {
        _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));

        if (!keyManager.IsInitialized)
            throw new InvalidOperationException("SealKeyManager must be initialized before creating SealCkksEngine.");

        _scale = scale > 0 ? scale : SealParameterPresets.DefaultCkksScale;

        var ctx = keyManager.Context!;
        _encryptor = new Encryptor(ctx, keyManager.PublicKey!);
        _decryptor = new Decryptor(ctx, keyManager.SecretKey!);
        _evaluator = new Evaluator(ctx);
        _encoder = new CKKSEncoder(ctx);
    }

    /// <inheritdoc/>
    public byte[] Encrypt(double value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var plain = EncodeDouble(value);
        using var encrypted = new Ciphertext();
        _encryptor.Encrypt(plain, encrypted);
        return SealCiphertextSerializer.Serialize(encrypted, SealCiphertextSerializer.SchemeCkks);
    }

    /// <inheritdoc/>
    public double Decrypt(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ciphertext);

        using var ct = SealCiphertextSerializer.Deserialize(ciphertext, Context);
        using var plain = new Plaintext();
        _decryptor.Decrypt(ct, plain);
        return DecodeDouble(plain);
    }

    /// <inheritdoc/>
    public byte[] Add(byte[] a, byte[] b)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        using var ctA = SealCiphertextSerializer.Deserialize(a, Context);
        using var ctB = SealCiphertextSerializer.Deserialize(b, Context);

        // Align levels before addition if they differ
        AlignLevels(ctA, ctB);

        using var result = new Ciphertext();
        _evaluator.Add(ctA, ctB, result);
        return SealCiphertextSerializer.Serialize(result, SealCiphertextSerializer.SchemeCkks);
    }

    /// <inheritdoc/>
    public byte[] Subtract(byte[] a, byte[] b)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        using var ctA = SealCiphertextSerializer.Deserialize(a, Context);
        using var ctB = SealCiphertextSerializer.Deserialize(b, Context);

        AlignLevels(ctA, ctB);

        using var result = new Ciphertext();
        _evaluator.Sub(ctA, ctB, result);
        return SealCiphertextSerializer.Serialize(result, SealCiphertextSerializer.SchemeCkks);
    }

    /// <inheritdoc/>
    public byte[] Multiply(byte[] a, byte[] b)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        using var ctA = SealCiphertextSerializer.Deserialize(a, Context);
        using var ctB = SealCiphertextSerializer.Deserialize(b, Context);

        AlignLevels(ctA, ctB);

        using var mulResult = new Ciphertext();
        _evaluator.Multiply(ctA, ctB, mulResult);

        // Relinearize to control ciphertext size
        using var relinResult = new Ciphertext();
        _evaluator.Relinearize(mulResult, _keyManager.RelinKeys!, relinResult);

        // Rescale to stabilize the scale after multiplication
        using var rescaled = new Ciphertext();
        _evaluator.RescaleToNext(relinResult, rescaled);

        return SealCiphertextSerializer.Serialize(rescaled, SealCiphertextSerializer.SchemeCkks);
    }

    /// <inheritdoc/>
    public byte[] Negate(byte[] a)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(a);

        using var ct = SealCiphertextSerializer.Deserialize(a, Context);
        using var result = new Ciphertext();
        _evaluator.Negate(ct, result);
        return SealCiphertextSerializer.Serialize(result, SealCiphertextSerializer.SchemeCkks);
    }

    /// <inheritdoc/>
    public byte[] Rescale(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ciphertext);

        using var ct = SealCiphertextSerializer.Deserialize(ciphertext, Context);
        using var result = new Ciphertext();
        _evaluator.RescaleToNext(ct, result);
        return SealCiphertextSerializer.Serialize(result, SealCiphertextSerializer.SchemeCkks);
    }

    /// <inheritdoc/>
    public int GetNoiseBudget(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ciphertext);

        // For CKKS, noise budget is measured by the chain index (remaining levels).
        // We return the chain index as a proxy for remaining computational depth.
        using var ct = SealCiphertextSerializer.Deserialize(ciphertext, Context);
        var contextData = Context.GetContextData(ct.ParmsId);
        return contextData != null ? (int)contextData.ChainIndex : 0;
    }

    private Plaintext EncodeDouble(double value)
    {
        var plain = new Plaintext();
        _encoder.Encode(value, _scale, plain);
        return plain;
    }

    private double DecodeDouble(Plaintext plain)
    {
        var result = new List<double>();
        _encoder.Decode(plain, result);
        return result.Count > 0 ? result[0] : 0.0;
    }

    /// <summary>
    /// Aligns two ciphertexts to the same level by mod-switching the higher-level
    /// ciphertext down to match the lower one.
    /// </summary>
    private void AlignLevels(Ciphertext a, Ciphertext b)
    {
        var contextDataA = Context.GetContextData(a.ParmsId);
        var contextDataB = Context.GetContextData(b.ParmsId);
        if (contextDataA == null || contextDataB == null) return;

        var levelA = contextDataA.ChainIndex;
        var levelB = contextDataB.ChainIndex;

        if (levelA > levelB)
        {
            _evaluator.ModSwitchTo(a, b.ParmsId, a);
        }
        else if (levelB > levelA)
        {
            _evaluator.ModSwitchTo(b, a.ParmsId, b);
        }
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
