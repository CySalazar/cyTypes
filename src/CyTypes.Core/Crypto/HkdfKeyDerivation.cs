using System.Security.Cryptography;

namespace CyTypes.Core.Crypto;

/// <summary>
/// Provides HKDF-based key derivation using SHA-512.
/// </summary>
public static class HkdfKeyDerivation
{
    /// <summary>
    /// Derives a cryptographic key from input key material using HKDF-SHA512.
    /// </summary>
    /// <param name="inputKeyMaterial">The source key material.</param>
    /// <param name="outputLength">Desired output key length in bytes (default 32).</param>
    /// <param name="salt">Optional salt for the extraction step.</param>
    /// <param name="info">Optional context/application-specific info for the expansion step.</param>
    /// <returns>The derived key bytes.</returns>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> inputKeyMaterial,
        int outputLength = 32,
        ReadOnlySpan<byte> salt = default,
        ReadOnlySpan<byte> info = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(outputLength, 0);

        var saltArray = salt.IsEmpty ? null : salt.ToArray();
        var infoArray = info.IsEmpty ? null : info.ToArray();

        return HKDF.DeriveKey(
            HashAlgorithmName.SHA512,
            inputKeyMaterial.ToArray(),
            outputLength,
            saltArray,
            infoArray);
    }
}
