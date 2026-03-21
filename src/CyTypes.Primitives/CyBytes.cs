using CyTypes.Core.Crypto;
using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure byte array. Drop-in replacement for byte[] that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// </summary>
public sealed class CyBytes : CyTypeBase<CyBytes, byte[]>, IEquatable<CyBytes>, IComparable<CyBytes>
{
    /// <summary>Length of the plaintext data (stored as metadata, no decrypt required).</summary>
    public int Length { get; }

    /// <summary>Initializes a new <see cref="CyBytes"/> with a clone of the specified byte array.</summary>
    public CyBytes(byte[] value, SecurityPolicy? policy = null) : base((byte[])value.Clone(), policy)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > BinarySerializer.MaxVariableLengthBytes)
            throw new ArgumentException(
                $"Byte array length ({value.Length}) exceeds maximum allowed size ({BinarySerializer.MaxVariableLengthBytes} bytes).",
                nameof(value));
        Length = value.Length;
    }

    /// <summary>Initializes a new <see cref="CyBytes"/> by cloning encrypted data without decryption.</summary>
    internal CyBytes(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager, int length)
        : base(encryptedBytes, policy, clonedKeyManager)
    {
        Length = length;
    }

    /// <inheritdoc/>
    protected override CyBytes CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager, Length);

    /// <inheritdoc/>
    protected override byte[] SerializeValue(byte[] value) => (byte[])value.Clone();
    /// <inheritdoc/>
    protected override byte[] DeserializeValue(byte[] data) => (byte[])data.Clone();

    /// <summary>Decrypts and returns the plaintext bytes. Marks compromise.</summary>
    public byte[] ToInsecureBytes() => ToInsecureValue();

    /// <summary>Lexicographic comparison of decrypted byte arrays.</summary>
    public int CompareTo(CyBytes? other)
    {
        if (other is null) return 1;
        return ((ReadOnlySpan<byte>)DecryptValue()).SequenceCompareTo(other.DecryptValue());
    }

    /// <inheritdoc/>
    public bool Equals(CyBytes? other)
    {
        if (other is null) return false;
        return ((ReadOnlySpan<byte>)DecryptValue()).SequenceEqual(other.DecryptValue());
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyBytes);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();

    /// <summary>Determines whether two CyBytes instances have equal content.</summary>
    public static bool operator ==(CyBytes? left, CyBytes? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return left.Equals(right);
    }

    /// <summary>Determines whether two CyBytes instances have different content.</summary>
    public static bool operator !=(CyBytes? left, CyBytes? right) => !(left == right);

    /// <summary>Less-than comparison (lexicographic).</summary>
    public static bool operator <(CyBytes left, CyBytes right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) < 0;
    }

    /// <summary>Greater-than comparison (lexicographic).</summary>
    public static bool operator >(CyBytes left, CyBytes right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) > 0;
    }

    /// <summary>Less-than-or-equal comparison (lexicographic).</summary>
    public static bool operator <=(CyBytes left, CyBytes right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) <= 0;
    }

    /// <summary>Greater-than-or-equal comparison (lexicographic).</summary>
    public static bool operator >=(CyBytes left, CyBytes right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) >= 0;
    }

    /// <summary>Encrypts a native byte array into a CyBytes.</summary>
    public static implicit operator CyBytes(byte[] value) => new(value);
    /// <summary>Decrypts the CyBytes to a native byte array. Marks compromise.</summary>
    public static explicit operator byte[](CyBytes cy) => cy.ToInsecureBytes();
}
