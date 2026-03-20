using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure 64-bit integer. Drop-in replacement for <see cref="long"/> that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers, or FHE via SEAL).
/// </summary>
public sealed partial class CyLong : CyTypeBase<CyLong, long>, ICyNumeric<CyLong>, IComparable<CyLong>, IEquatable<CyLong>
{
    /// <summary>Indicates whether fully homomorphic encryption is supported under the current policy.</summary>
    public bool SupportsFhe => Policy.Arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull;

    /// <summary>Initializes a new <see cref="CyLong"/> by encrypting the specified value.</summary>
    public CyLong(long value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Initializes a new <see cref="CyLong"/> from pre-existing FHE ciphertext bytes.</summary>
    internal CyLong(byte[] fheCiphertext, SecurityPolicy policy) : base(fheCiphertext, policy, default(FheCiphertextTag)) { }

    /// <summary>Serializes a long value to its byte representation.</summary>
    protected override byte[] SerializeValue(long value) => BitConverter.GetBytes(value);
    /// <summary>Deserializes a long value from its byte representation.</summary>
    protected override long DeserializeValue(byte[] data) => BitConverter.ToInt64(data);

    /// <summary>Decrypts and returns the plaintext long, marking this instance as compromised.</summary>
    public long ToInsecureLong() => ToInsecureValue();

    /// <summary>The smallest possible value of a <see cref="CyLong"/>.</summary>
    public static CyLong MinValue => new(long.MinValue);
    /// <summary>The largest possible value of a <see cref="CyLong"/>.</summary>
    public static CyLong MaxValue => new(long.MaxValue);

    /// <summary>Parses the string representation of a long and returns an encrypted <see cref="CyLong"/>.</summary>
    public static CyLong Parse(string s, IFormatProvider? provider = null)
        => new(long.Parse(s, provider));

    /// <summary>Parses the string representation of a long and returns an encrypted <see cref="CyLong"/>.</summary>
    public static CyLong Parse(ReadOnlySpan<char> s, IFormatProvider? provider = null)
        => new(long.Parse(s, provider));

    /// <summary>Tries to parse the string representation of a long into an encrypted <see cref="CyLong"/>.</summary>
    public static bool TryParse(string? s, out CyLong? result)
    {
        if (long.TryParse(s, out var value))
        {
            result = new CyLong(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Tries to parse the string representation of a long into an encrypted <see cref="CyLong"/>.</summary>
    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out CyLong? result)
    {
        if (long.TryParse(s, provider, out var value))
        {
            result = new CyLong(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Compares this instance to another <see cref="CyLong"/> by decrypted value.</summary>
    public int CompareTo(CyLong? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }
}
