using System.Security.Cryptography;
using CyTypes.Core.Crypto.Interfaces;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace CyTypes.Core.Crypto;

/// <summary>
/// AES-SIV (RFC 5297) deterministic encryption engine for equality-preserving operations.
/// Same plaintext + same key always produces the same ciphertext, enabling encrypted
/// equality checks without decryption.
/// </summary>
/// <remarks>
/// SECURITY: Deterministic encryption leaks equality patterns (IND-CPA but not IND-CCA2).
/// This is intentional for <see cref="IDeterministicEncryptionEngine"/> — the trade-off
/// enables encrypted equality testing without exposing plaintext.
/// Implementation uses AES-CMAC for S2V (string-to-vector) and AES-CTR for encryption.
/// </remarks>
public sealed class AesSivEngine : IDeterministicEncryptionEngine, IDisposable
{
    private readonly byte[] _macKey;   // First 16 bytes: CMAC sub-key
    private readonly byte[] _encKey;   // Last 16 bytes: CTR encryption key
    private bool _disposed;

    /// <summary>
    /// Initializes a new AES-SIV engine with the specified 32-byte key.
    /// The key is split: first 16 bytes for CMAC, last 16 bytes for CTR.
    /// </summary>
    public AesSivEngine(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("AES-SIV key must be 32 bytes (16 for CMAC + 16 for CTR).", nameof(key));

        _macKey = new byte[16];
        _encKey = new byte[16];
        Array.Copy(key, 0, _macKey, 0, 16);
        Array.Copy(key, 16, _encKey, 0, 16);
    }

    /// <summary>
    /// Creates an AES-SIV engine with a randomly generated 32-byte key.
    /// </summary>
    public static AesSivEngine CreateWithRandomKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        try
        {
            return new AesSivEngine(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc/>
    public byte[] EncryptDeterministic(byte[] plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(plaintext);

        // Step 1: Compute SIV (synthetic IV) = CMAC(macKey, plaintext)
        var siv = ComputeCmac(_macKey, plaintext);

        // Step 2: AES-CTR encrypt plaintext using SIV as the IV (clear bits 31 and 63 per RFC 5297)
        var ctrIv = (byte[])siv.Clone();
        ctrIv[8] &= 0x7F;
        ctrIv[12] &= 0x7F;

        var ciphertext = AesCtrTransform(_encKey, ctrIv, plaintext);

        // Output: SIV (16 bytes) || ciphertext
        var output = new byte[16 + ciphertext.Length];
        Array.Copy(siv, 0, output, 0, 16);
        Array.Copy(ciphertext, 0, output, 16, ciphertext.Length);
        return output;
    }

    /// <inheritdoc/>
    public byte[] DecryptDeterministic(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ciphertext);

        if (ciphertext.Length < 16)
            throw new ArgumentException("Ciphertext too short for AES-SIV (minimum 16 bytes for SIV tag).", nameof(ciphertext));

        // Step 1: Extract SIV and encrypted data
        var siv = new byte[16];
        Array.Copy(ciphertext, 0, siv, 0, 16);
        var encData = new byte[ciphertext.Length - 16];
        if (encData.Length > 0)
            Array.Copy(ciphertext, 16, encData, 0, encData.Length);

        // Step 2: AES-CTR decrypt using SIV as IV
        var ctrIv = (byte[])siv.Clone();
        ctrIv[8] &= 0x7F;
        ctrIv[12] &= 0x7F;

        var plaintext = AesCtrTransform(_encKey, ctrIv, encData);

        // Step 3: Verify SIV by recomputing CMAC
        var expectedSiv = ComputeCmac(_macKey, plaintext);
        if (!CryptographicOperations.FixedTimeEquals(siv, expectedSiv))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("AES-SIV authentication failed: SIV tag mismatch.");
        }

        return plaintext;
    }

    /// <inheritdoc/>
    public bool CiphertextEquals(byte[] a, byte[] b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static byte[] ComputeCmac(byte[] key, byte[] data)
    {
        var mac = new CMac(new AesEngine(), 128);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    private static byte[] AesCtrTransform(byte[] key, byte[] iv, byte[] input)
    {
        if (input.Length == 0)
            return [];

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        var output = new byte[input.Length];
        var counter = (byte[])iv.Clone();
        var keystream = new byte[16];

        using var encryptor = aes.CreateEncryptor();

        for (int offset = 0; offset < input.Length; offset += 16)
        {
            encryptor.TransformBlock(counter, 0, 16, keystream, 0);

            int blockLen = Math.Min(16, input.Length - offset);
            for (int i = 0; i < blockLen; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);

            // Increment counter (big-endian)
            for (int i = 15; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
            }
        }

        CryptographicOperations.ZeroMemory(keystream);
        return output;
    }

    /// <summary>Securely zeros the key material.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_macKey);
        CryptographicOperations.ZeroMemory(_encKey);
    }
}
