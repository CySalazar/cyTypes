using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure single-precision floating point. Drop-in replacement for <see cref="float"/>
/// that keeps data encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// </summary>
public sealed partial class CyFloat : CyTypeBase<CyFloat, float>, ICyNumeric<CyFloat>, IComparable<CyFloat>, IEquatable<CyFloat>
{
    /// <summary>Indicates whether fully homomorphic encryption is supported.</summary>
    [Obsolete("Floating-point FHE requires the CKKS scheme (Phase 3b). BFV supports integer types only. This property always returns false.")]
    public bool SupportsFhe => false;

    /// <summary>Initializes a new <see cref="CyFloat"/> by encrypting the specified value.</summary>
    public CyFloat(float value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Initializes a new <see cref="CyFloat"/> by cloning encrypted data without decryption.</summary>
    internal CyFloat(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        : base(encryptedBytes, policy, clonedKeyManager) { }

    /// <inheritdoc/>
    protected override CyFloat CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager);

    /// <summary>Serializes a float value to its byte representation.</summary>
    protected override byte[] SerializeValue(float value) => BitConverter.GetBytes(value);

    /// <summary>Deserializes a float value from its byte representation.</summary>
    protected override float DeserializeValue(byte[] data)
    {
        if (data.Length < 4)
            throw new ArgumentException($"Float deserialization requires 4 bytes, got {data.Length}.", nameof(data));
        return BitConverter.ToSingle(data);
    }

    /// <summary>Decrypts and returns the plaintext float, marking this instance as compromised.</summary>
    public float ToInsecureFloat() => ToInsecureValue();

    /// <summary>The smallest possible value of a <see cref="CyFloat"/>.</summary>
    public static CyFloat MinValue => new(float.MinValue);
    /// <summary>The largest possible value of a <see cref="CyFloat"/>.</summary>
    public static CyFloat MaxValue => new(float.MaxValue);
    /// <summary>Represents positive infinity.</summary>
    public static CyFloat PositiveInfinity => new(float.PositiveInfinity);
    /// <summary>Represents negative infinity.</summary>
    public static CyFloat NegativeInfinity => new(float.NegativeInfinity);
    /// <summary>Represents Not-a-Number (NaN).</summary>
    public static CyFloat NaN => new(float.NaN);
    /// <summary>Represents the smallest positive value greater than zero.</summary>
    public static CyFloat Epsilon => new(float.Epsilon);

    /// <summary>Parses the string representation of a float and returns an encrypted <see cref="CyFloat"/>.</summary>
    public static CyFloat Parse(string s, IFormatProvider? provider = null)
        => new(float.Parse(s, provider));

    /// <summary>Parses the string representation of a float and returns an encrypted <see cref="CyFloat"/>.</summary>
    public static CyFloat Parse(ReadOnlySpan<char> s, IFormatProvider? provider = null)
        => new(float.Parse(s, provider));

    /// <summary>Tries to parse the string representation of a float into an encrypted <see cref="CyFloat"/>.</summary>
    public static bool TryParse(string? s, out CyFloat? result)
    {
        if (float.TryParse(s, out var value))
        {
            result = new CyFloat(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Tries to parse the string representation of a float into an encrypted <see cref="CyFloat"/>.</summary>
    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out CyFloat? result)
    {
        if (float.TryParse(s, provider, out var value))
        {
            result = new CyFloat(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Compares this instance to another <see cref="CyFloat"/> by decrypted value.</summary>
    public int CompareTo(CyFloat? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }
}
