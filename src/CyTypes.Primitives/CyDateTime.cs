using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure DateTime. Drop-in replacement for <see cref="DateTime"/> that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// </summary>
public sealed partial class CyDateTime : CyTypeBase<CyDateTime, DateTime>, IComparable<CyDateTime>, IEquatable<CyDateTime>
{
    /// <summary>Initializes a new <see cref="CyDateTime"/> with the specified DateTime value.</summary>
    public CyDateTime(DateTime value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Initializes a new <see cref="CyDateTime"/> by cloning encrypted data without decryption.</summary>
    internal CyDateTime(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        : base(encryptedBytes, policy, clonedKeyManager) { }

    /// <inheritdoc/>
    protected override CyDateTime CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager);

    /// <inheritdoc/>
    protected override byte[] SerializeValue(DateTime value) => BitConverter.GetBytes(value.Ticks);

    /// <inheritdoc/>
    protected override DateTime DeserializeValue(byte[] data)
    {
        if (data.Length < 8)
            throw new ArgumentException($"DateTime deserialization requires 8 bytes, got {data.Length}.", nameof(data));
        return new DateTime(BitConverter.ToInt64(data), DateTimeKind.Utc);
    }

    /// <summary>Decrypts and returns the plaintext DateTime. Marks compromise.</summary>
    public DateTime ToInsecureDateTime() => ToInsecureValue();

    /// <summary>Compares two <see cref="CyDateTime"/> values by their underlying DateTime.</summary>
    public int CompareTo(CyDateTime? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }
}
