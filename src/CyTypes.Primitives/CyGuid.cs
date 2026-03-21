using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure GUID. Drop-in replacement for <see cref="Guid"/> that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// </summary>
public sealed class CyGuid : CyTypeBase<CyGuid, Guid>, IEquatable<CyGuid>, IComparable<CyGuid>
{
    /// <summary>Initializes a new <see cref="CyGuid"/> by encrypting the specified GUID.</summary>
    public CyGuid(Guid value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Initializes a new <see cref="CyGuid"/> by cloning encrypted data without decryption.</summary>
    internal CyGuid(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        : base(encryptedBytes, policy, clonedKeyManager) { }

    /// <inheritdoc/>
    protected override CyGuid CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager);

    /// <inheritdoc/>
    protected override byte[] SerializeValue(Guid value) => value.ToByteArray();
    /// <inheritdoc/>
    protected override Guid DeserializeValue(byte[] data) => new(data);

    /// <summary>Decrypts and returns the plaintext GUID. Marks compromise.</summary>
    public Guid ToInsecureGuid() => ToInsecureValue();

    /// <summary>Compares two CyGuid values by their decrypted Guid.</summary>
    public int CompareTo(CyGuid? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }

    /// <inheritdoc/>
    public bool Equals(CyGuid? other)
    {
        if (other is null) return false;
        return DecryptValue() == other.DecryptValue();
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyGuid);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();

    /// <summary>Determines whether two CyGuid instances are equal.</summary>
    public static bool operator ==(CyGuid? left, CyGuid? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;
        return left.Equals(right);
    }

    /// <summary>Determines whether two CyGuid instances are not equal.</summary>
    public static bool operator !=(CyGuid? left, CyGuid? right) => !(left == right);

    /// <summary>Less-than comparison by Guid value.</summary>
    public static bool operator <(CyGuid left, CyGuid right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) < 0;
    }

    /// <summary>Greater-than comparison by Guid value.</summary>
    public static bool operator >(CyGuid left, CyGuid right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) > 0;
    }

    /// <summary>Less-than-or-equal comparison by Guid value.</summary>
    public static bool operator <=(CyGuid left, CyGuid right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) <= 0;
    }

    /// <summary>Greater-than-or-equal comparison by Guid value.</summary>
    public static bool operator >=(CyGuid left, CyGuid right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) >= 0;
    }

    /// <summary>Encrypts a native Guid into a CyGuid.</summary>
    public static implicit operator CyGuid(Guid value) => new(value);
    /// <summary>Decrypts the CyGuid to a native Guid. Marks compromise.</summary>
    public static explicit operator Guid(CyGuid cy) => cy.ToInsecureGuid();
}
