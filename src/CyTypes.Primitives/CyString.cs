using System.Text;
using CyTypes.Core.Crypto;
using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure string. Drop-in replacement for <see cref="string"/> that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// Unlike System.String, CyString is mutable (re-encryptable), disposable, and
/// never subject to string interning or GC relocation of plaintext.
/// </summary>
/// <remarks>
/// <b>Metadata leak:</b> The <see cref="Length"/> property is exposed without decryption.
/// An attacker with memory access can infer plaintext length. This is an intentional
/// trade-off for performance — use fixed-length padding if length must be hidden.
/// </remarks>
public sealed partial class CyString : CyTypeBase<CyString, string>, IEquatable<CyString>, IComparable<CyString>
{
    /// <summary>Length of the plaintext string (stored as metadata, no decrypt required).</summary>
    /// <remarks>
    /// SECURITY: This value is not encrypted. It reveals the plaintext string length
    /// to anyone with access to this instance. See class remarks for mitigation.
    /// For a length value derived from decryption (no metadata leak), see <see cref="SecureLength"/>.
    /// </remarks>
    public int Length { get; }

    /// <summary>True if Length is 0.</summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Returns the length of the plaintext string by decrypting the value.
    /// Unlike <see cref="Length"/>, this does not rely on stored metadata.
    /// Does not mark the instance as compromised (only an int is returned).
    /// </summary>
    public int SecureLength => DecryptValue().Length;

    /// <summary>Initializes a new CyString by encrypting the specified string value.</summary>
    public CyString(string value, SecurityPolicy? policy = null) : base(value, policy)
    {
        ArgumentNullException.ThrowIfNull(value);
        var byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount > BinarySerializer.MaxVariableLengthBytes)
            throw new ArgumentException(
                $"String UTF-8 byte length ({byteCount}) exceeds maximum allowed size ({BinarySerializer.MaxVariableLengthBytes} bytes).",
                nameof(value));
        Length = value.Length;
    }

    /// <summary>Initializes a new <see cref="CyString"/> by cloning encrypted data without decryption.</summary>
    internal CyString(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager, int length)
        : base(encryptedBytes, policy, clonedKeyManager)
    {
        Length = length;
    }

    /// <inheritdoc/>
    protected override CyString CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager, Length);

    /// <inheritdoc/>
    protected override byte[] SerializeValue(string value) => Encoding.UTF8.GetBytes(value);
    /// <inheritdoc/>
    protected override string DeserializeValue(byte[] data) => Encoding.UTF8.GetString(data);

    /// <summary>
    /// Explicitly decrypts and returns the plaintext string.
    /// Marks this instance as compromised. Deliberately verbose name.
    /// </summary>
    public string ToInsecureString() => ToInsecureValue();

    /// <summary>Returns true if the specified CyString is null or empty.</summary>
    public static bool IsNullOrEmpty(CyString? value) => value is null || value.IsEmpty;

    /// <summary>Ordinal comparison of decrypted string values.</summary>
    public int CompareTo(CyString? other)
    {
        if (other is null) return 1;
        return string.CompareOrdinal(DecryptValue(), other.DecryptValue());
    }

    /// <summary>Returns true if the specified CyString is null, empty, or contains only whitespace.</summary>
    /// <remarks>
    /// SECURITY: Decrypts the value internally but does not mark the instance as compromised,
    /// because only a boolean result is returned — no plaintext escapes the enclave.
    /// This is consistent with other query methods (Contains, StartsWith, etc.).
    /// </remarks>
    public static bool IsNullOrWhiteSpace(CyString? value)
    {
        if (value is null) return true;
        if (value.IsEmpty) return true;
        var plain = value.DecryptValue();
        return string.IsNullOrWhiteSpace(plain);
    }
}
