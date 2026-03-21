using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure 32-bit integer. Drop-in replacement for <see cref="int"/> that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers, or FHE via SEAL).
/// </summary>
public sealed partial class CyInt : CyTypeBase<CyInt, int>, ICyNumeric<CyInt>, IComparable<CyInt>, IEquatable<CyInt>
{
    /// <summary>Indicates whether fully homomorphic encryption is supported under the current policy.</summary>
    public bool SupportsFhe => Policy.Arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull;

    /// <summary>Initializes a new <see cref="CyInt"/> by encrypting the specified value.</summary>
    public CyInt(int value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Initializes a new <see cref="CyInt"/> from pre-existing FHE ciphertext bytes.</summary>
    internal CyInt(byte[] fheCiphertext, SecurityPolicy policy) : base(fheCiphertext, policy, default(FheCiphertextTag)) { }

    /// <summary>Initializes a new <see cref="CyInt"/> by cloning encrypted data without decryption.</summary>
    internal CyInt(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        : base(encryptedBytes, policy, clonedKeyManager) { }

    /// <inheritdoc/>
    protected override CyInt CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager);

    /// <summary>Serializes an int value to its byte representation.</summary>
    protected override byte[] SerializeValue(int value) => BitConverter.GetBytes(value);
    /// <summary>Deserializes an int value from its byte representation.</summary>
    protected override int DeserializeValue(byte[] data) => BitConverter.ToInt32(data);

    /// <summary>
    /// Explicitly decrypts and returns the plaintext integer.
    /// Marks this instance as compromised. Deliberately verbose name.
    /// </summary>
    public int ToInsecureInt() => ToInsecureValue();

    /// <summary>The smallest possible value of a <see cref="CyInt"/>.</summary>
    public static CyInt MinValue => new(int.MinValue);
    /// <summary>The largest possible value of a <see cref="CyInt"/>.</summary>
    public static CyInt MaxValue => new(int.MaxValue);

    /// <summary>Parses the string representation of an integer and returns an encrypted <see cref="CyInt"/>.</summary>
    public static CyInt Parse(string s, IFormatProvider? provider = null)
        => new(int.Parse(s, provider));

    /// <summary>Parses the string representation of an integer and returns an encrypted <see cref="CyInt"/>.</summary>
    public static CyInt Parse(ReadOnlySpan<char> s, IFormatProvider? provider = null)
        => new(int.Parse(s, provider));

    /// <summary>Tries to parse the string representation of an integer into an encrypted <see cref="CyInt"/>.</summary>
    public static bool TryParse(string? s, out CyInt? result)
    {
        if (int.TryParse(s, out var value))
        {
            result = new CyInt(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Tries to parse the string representation of an integer into an encrypted <see cref="CyInt"/>.</summary>
    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out CyInt? result)
    {
        if (int.TryParse(s, provider, out var value))
        {
            result = new CyInt(value);
            return true;
        }
        result = null;
        return false;
    }

    /// <summary>Compares this instance to another <see cref="CyInt"/> by decrypted value.</summary>
    public int CompareTo(CyInt? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }
}
