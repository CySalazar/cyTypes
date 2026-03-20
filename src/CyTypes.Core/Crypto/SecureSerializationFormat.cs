using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace CyTypes.Core.Crypto;

/// <summary>
/// Binary envelope format with HMAC-SHA512 integrity verification.
/// Layout: [version:1] [keyId:16] [nonce:12] [ciphertext:N] [HMAC-SHA512:64]
/// </summary>
public static class SecureSerializationFormat
{
    /// <summary>The current envelope format version.</summary>
    public const byte CurrentVersion = 1;

    /// <summary>Length in bytes of the version field.</summary>
    public const int VersionLength = 1;

    /// <summary>Length in bytes of the key identifier field.</summary>
    public const int KeyIdLength = 16;

    /// <summary>Length in bytes of the nonce field.</summary>
    public const int NonceLength = 12;

    /// <summary>Length in bytes of the HMAC-SHA512 field.</summary>
    public const int HmacLength = 64;

    private const int HeaderLength = VersionLength + KeyIdLength + NonceLength;
    private const int MinEnvelopeLength = HeaderLength + HmacLength;

    private static readonly byte[] HmacInfo = Encoding.UTF8.GetBytes("CyTypes.SecureSerialization.HMAC");

    /// <summary>
    /// Builds a secure envelope around the given ciphertext.
    /// </summary>
    /// <param name="ciphertext">The encrypted payload.</param>
    /// <param name="keyId">The key identifier to embed in the envelope.</param>
    /// <param name="hmacKey">The root key from which the HMAC subkey is derived via HKDF.</param>
    /// <returns>The complete envelope bytes.</returns>
    public static byte[] Serialize(ReadOnlySpan<byte> ciphertext, Guid keyId, ReadOnlySpan<byte> hmacKey)
    {
        var envelopeLength = HeaderLength + ciphertext.Length + HmacLength;
        var envelope = new byte[envelopeLength];

        // Version
        envelope[0] = CurrentVersion;

        // KeyId
        keyId.TryWriteBytes(envelope.AsSpan(VersionLength, KeyIdLength));

        // Nonce (random 12 bytes)
        RandomNumberGenerator.Fill(envelope.AsSpan(VersionLength + KeyIdLength, NonceLength));

        // Ciphertext
        ciphertext.CopyTo(envelope.AsSpan(HeaderLength));

        // Derive HMAC subkey via HKDF
        var subkey = HkdfKeyDerivation.DeriveKey(hmacKey, outputLength: 64, info: HmacInfo);
        try
        {
            // Compute HMAC-SHA512 over version | keyId | nonce | ciphertext
            var authenticatedSpan = envelope.AsSpan(0, HeaderLength + ciphertext.Length);
            var hmac = ComputeHmac(subkey, authenticatedSpan);

            hmac.CopyTo(envelope.AsSpan(HeaderLength + ciphertext.Length));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
        }

        return envelope;
    }

    /// <summary>
    /// Verifies the HMAC and extracts the key ID and ciphertext from the envelope.
    /// </summary>
    /// <param name="envelope">The complete envelope bytes.</param>
    /// <param name="hmacKey">The root key from which the HMAC subkey is derived via HKDF.</param>
    /// <returns>The extracted key ID and ciphertext.</returns>
    /// <exception cref="SecurityException">Thrown when the HMAC does not match.</exception>
    /// <exception cref="ArgumentException">Thrown when the envelope is too small or the version is unsupported.</exception>
    public static (Guid KeyId, byte[] Ciphertext) Deserialize(ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> hmacKey)
    {
        if (envelope.Length < MinEnvelopeLength)
            throw new ArgumentException(
                $"Envelope is too small. Minimum size is {MinEnvelopeLength} bytes, got {envelope.Length}.",
                nameof(envelope));

        // Version check
        byte version = envelope[0];
        if (version != CurrentVersion)
            throw new ArgumentException(
                $"Unsupported envelope version {version}. Expected {CurrentVersion}.",
                nameof(envelope));

        // Extract fields
        var keyId = new Guid(envelope.Slice(VersionLength, KeyIdLength));
        var ciphertextLength = envelope.Length - HeaderLength - HmacLength;
        var ciphertext = envelope.Slice(HeaderLength, ciphertextLength);
        var providedHmac = envelope.Slice(envelope.Length - HmacLength, HmacLength);

        // Derive HMAC subkey via HKDF
        var subkey = HkdfKeyDerivation.DeriveKey(hmacKey, outputLength: 64, info: HmacInfo);
        try
        {
            // Compute expected HMAC over version | keyId | nonce | ciphertext
            var authenticatedSpan = envelope[..(HeaderLength + ciphertextLength)];
            var expectedHmac = ComputeHmac(subkey, authenticatedSpan);

            if (!CryptographicOperations.FixedTimeEquals(expectedHmac, providedHmac))
                throw new SecurityException("HMAC verification failed. The envelope has been tampered with.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
        }

        return (keyId, ciphertext.ToArray());
    }

    /// <summary>
    /// Verifies the HMAC of a secure envelope without fully deserializing it.
    /// </summary>
    /// <param name="envelope">The complete envelope bytes.</param>
    /// <param name="hmacKey">The root key from which the HMAC subkey is derived via HKDF.</param>
    /// <returns><c>true</c> if the HMAC is valid; otherwise <c>false</c>.</returns>
    public static bool VerifySecureBytes(ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> hmacKey)
    {
        if (envelope.Length < MinEnvelopeLength)
            return false;

        if (envelope[0] != CurrentVersion)
            return false;

        var ciphertextLength = envelope.Length - HeaderLength - HmacLength;
        var providedHmac = envelope.Slice(envelope.Length - HmacLength, HmacLength);

        var subkey = HkdfKeyDerivation.DeriveKey(hmacKey, outputLength: 64, info: HmacInfo);
        try
        {
            var authenticatedSpan = envelope[..(HeaderLength + ciphertextLength)];
            var expectedHmac = ComputeHmac(subkey, authenticatedSpan);

            return CryptographicOperations.FixedTimeEquals(expectedHmac, providedHmac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
        }
    }

    private static byte[] ComputeHmac(byte[] key, ReadOnlySpan<byte> data)
    {
        var hmac = new byte[HmacLength];
        HMACSHA512.HashData(key, data, hmac);
        return hmac;
    }
}
