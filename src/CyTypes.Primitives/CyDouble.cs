using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure double-precision floating point. Drop-in replacement for <see cref="double"/>
/// that keeps data encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// </summary>
public sealed partial class CyDouble : CyTypeBase<CyDouble, double>, ICyNumeric<CyDouble>, IComparable<CyDouble>, IEquatable<CyDouble>
{
    /// <summary>Indicates whether fully homomorphic encryption is supported.</summary>
    [Obsolete("FHE support is not yet implemented. Planned for Phase 3 (SEAL integration). This property always returns false.")]
    public bool SupportsFhe => false;

    /// <summary>Initializes a new <see cref="CyDouble"/> by encrypting the specified value.</summary>
    public CyDouble(double value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Serializes a double value to its byte representation.</summary>
    protected override byte[] SerializeValue(double value) => BitConverter.GetBytes(value);
    /// <summary>Deserializes a double value from its byte representation.</summary>
    protected override double DeserializeValue(byte[] data) => BitConverter.ToDouble(data);

    /// <summary>Decrypts and returns the plaintext double, marking this instance as compromised.</summary>
    public double ToInsecureDouble() => ToInsecureValue();

    /// <summary>The smallest possible value of a <see cref="CyDouble"/>.</summary>
    public static CyDouble MinValue => new(double.MinValue);
    /// <summary>The largest possible value of a <see cref="CyDouble"/>.</summary>
    public static CyDouble MaxValue => new(double.MaxValue);
    /// <summary>Represents positive infinity.</summary>
    public static CyDouble PositiveInfinity => new(double.PositiveInfinity);
    /// <summary>Represents negative infinity.</summary>
    public static CyDouble NegativeInfinity => new(double.NegativeInfinity);
    /// <summary>Represents Not-a-Number (NaN).</summary>
    public static CyDouble NaN => new(double.NaN);
    /// <summary>Represents the smallest positive value greater than zero.</summary>
    public static CyDouble Epsilon => new(double.Epsilon);

    /// <summary>Parses the string representation of a double and returns an encrypted <see cref="CyDouble"/>.</summary>
    public static CyDouble Parse(string s, IFormatProvider? provider = null)
        => new(double.Parse(s, provider));

    /// <summary>Parses the string representation of a double and returns an encrypted <see cref="CyDouble"/>.</summary>
    public static CyDouble Parse(ReadOnlySpan<char> s, IFormatProvider? provider = null)
        => new(double.Parse(s, provider));

    /// <summary>Tries to parse the string representation of a double into an encrypted <see cref="CyDouble"/>.</summary>
    public static bool TryParse(string? s, out CyDouble? result)
    {
        if (double.TryParse(s, out var value))
        {
            result = new CyDouble(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Tries to parse the string representation of a double into an encrypted <see cref="CyDouble"/>.</summary>
    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out CyDouble? result)
    {
        if (double.TryParse(s, provider, out var value))
        {
            result = new CyDouble(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Compares this instance to another <see cref="CyDouble"/> by decrypted value.</summary>
    public int CompareTo(CyDouble? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }
}
