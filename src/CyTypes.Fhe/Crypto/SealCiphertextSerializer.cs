using Microsoft.Research.SEAL;

namespace CyTypes.Fhe.Crypto;

/// <summary>
/// Serializes and deserializes SEAL Ciphertext to/from byte arrays with a magic header
/// to distinguish FHE ciphertexts from AES-GCM ciphertexts.
/// </summary>
public static class SealCiphertextSerializer
{
    /// <summary>Magic header byte for FHE ciphertexts.</summary>
    private const byte MagicFhe = 0xFE;

    /// <summary>BFV scheme marker.</summary>
    public const byte SchemeBfv = 0x01;

    /// <summary>CKKS scheme marker.</summary>
    public const byte SchemeCkks = 0x02;

    /// <summary>
    /// Serializes a SEAL Ciphertext to a byte array with the FHE magic header.
    /// </summary>
    public static byte[] Serialize(Ciphertext ciphertext, byte schemeMarker = SchemeBfv)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        using var ms = new MemoryStream();
        ms.WriteByte(MagicFhe);
        ms.WriteByte(schemeMarker);
        ciphertext.Save(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Deserializes a byte array back to a SEAL Ciphertext, validating the magic header.
    /// </summary>
    public static Ciphertext Deserialize(byte[] data, SEALContext context)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(context);

        if (data.Length < 2 || data[0] != MagicFhe)
            throw new InvalidOperationException("Data is not an FHE ciphertext (missing magic header 0xFE).");

        using var ms = new MemoryStream(data, 2, data.Length - 2);
        var ct = new Ciphertext();
        ct.Load(context, ms);
        return ct;
    }

    /// <summary>
    /// Returns true if the data begins with the FHE magic header.
    /// </summary>
    public static bool IsFheCiphertext(byte[] data)
    {
        return data != null && data.Length >= 2 && data[0] == MagicFhe;
    }

    /// <summary>
    /// Returns the scheme marker from the data, or -1 if not an FHE ciphertext.
    /// </summary>
    public static int GetSchemeMarker(byte[] data)
    {
        if (!IsFheCiphertext(data)) return -1;
        return data[1];
    }
}
