using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure decimal. Drop-in replacement for <see cref="decimal"/> that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// </summary>
public sealed partial class CyDecimal : CyTypeBase<CyDecimal, decimal>, ICyNumeric<CyDecimal>, IComparable<CyDecimal>, IEquatable<CyDecimal>
{
    /// <summary>
    /// Indicates whether fully homomorphic encryption is supported for this instance's policy.
    /// CKKS uses approximate arithmetic (~15 significant digits); decimal's 28-29 digit precision is NOT preserved.
    /// </summary>
    public bool SupportsFhe => Policy.Arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull;

    /// <summary>Initializes a new <see cref="CyDecimal"/> with the specified decimal value.</summary>
    public CyDecimal(decimal value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Initializes a new <see cref="CyDecimal"/> from pre-existing FHE ciphertext bytes.</summary>
    internal CyDecimal(byte[] fheCiphertext, SecurityPolicy policy)
        : base(fheCiphertext, policy, default(FheCiphertextTag)) { }

    /// <summary>Initializes a new <see cref="CyDecimal"/> by cloning encrypted data without decryption.</summary>
    internal CyDecimal(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        : base(encryptedBytes, policy, clonedKeyManager) { }

    /// <inheritdoc/>
    protected override CyDecimal CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager);

    /// <inheritdoc/>
    protected override byte[] SerializeValue(decimal value)
    {
        var bits = decimal.GetBits(value);
        var bytes = new byte[16];
        for (var i = 0; i < 4; i++)
            BitConverter.GetBytes(bits[i]).CopyTo(bytes, i * 4);
        return bytes;
    }

    /// <inheritdoc/>
    protected override decimal DeserializeValue(byte[] data)
    {
        if (data.Length < 16)
            throw new ArgumentException($"Decimal deserialization requires 16 bytes, got {data.Length}.", nameof(data));

        var bits = new int[4];
        for (var i = 0; i < 4; i++)
            bits[i] = BitConverter.ToInt32(data, i * 4);
        return new decimal(bits);
    }

    /// <summary>Decrypts and returns the plaintext decimal. Marks compromise.</summary>
    public decimal ToInsecureDecimal() => ToInsecureValue();

    /// <summary>The smallest possible value of a <see cref="CyDecimal"/>.</summary>
    public static CyDecimal MinValue => new(decimal.MinValue);
    /// <summary>The largest possible value of a <see cref="CyDecimal"/>.</summary>
    public static CyDecimal MaxValue => new(decimal.MaxValue);
    /// <summary>Represents the number zero (0).</summary>
    public static CyDecimal Zero => new(decimal.Zero);
    /// <summary>Represents the number one (1).</summary>
    public static CyDecimal One => new(decimal.One);
    /// <summary>Represents the number negative one (-1).</summary>
    public static CyDecimal MinusOne => new(decimal.MinusOne);

    /// <summary>Parses the string representation of a decimal and returns an encrypted <see cref="CyDecimal"/>.</summary>
    public static CyDecimal Parse(string s, IFormatProvider? provider = null)
        => new(decimal.Parse(s, provider));

    /// <summary>Parses the string representation of a decimal and returns an encrypted <see cref="CyDecimal"/>.</summary>
    public static CyDecimal Parse(ReadOnlySpan<char> s, IFormatProvider? provider = null)
        => new(decimal.Parse(s, provider));

    /// <summary>Tries to parse the string representation of a decimal into an encrypted <see cref="CyDecimal"/>.</summary>
    public static bool TryParse(string? s, out CyDecimal? result)
    {
        if (decimal.TryParse(s, out var value))
        {
            result = new CyDecimal(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Tries to parse the string representation of a decimal into an encrypted <see cref="CyDecimal"/>.</summary>
    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out CyDecimal? result)
    {
        if (decimal.TryParse(s, provider, out var value))
        {
            result = new CyDecimal(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Compares two <see cref="CyDecimal"/> values by their underlying decimal.</summary>
    public int CompareTo(CyDecimal? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }
}
