using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Primitives.Shared;

namespace CyTypes.Primitives;

/// <summary>
/// Secure boolean. Drop-in replacement for <see cref="bool"/> that keeps data
/// encrypted in memory at all times (AES-256-GCM in pinned buffers).
/// </summary>
public sealed partial class CyBool : CyTypeBase<CyBool, bool>, IEquatable<CyBool>, IComparable<CyBool>
{
    /// <summary>Initializes a new <see cref="CyBool"/> with the specified boolean value.</summary>
    public CyBool(bool value, SecurityPolicy? policy = null) : base(value, policy) { }

    /// <summary>Initializes a new <see cref="CyBool"/> by cloning encrypted data without decryption.</summary>
    internal CyBool(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        : base(encryptedBytes, policy, clonedKeyManager) { }

    /// <inheritdoc/>
    protected override CyBool CreateClone(byte[] encryptedBytes, SecurityPolicy policy, KeyManager clonedKeyManager)
        => new(encryptedBytes, policy, clonedKeyManager);

    /// <inheritdoc/>
    protected override byte[] SerializeValue(bool value) => [(byte)(value ? 1 : 0)];
    /// <inheritdoc/>
    protected override bool DeserializeValue(byte[] data) => data[0] != 0;

    /// <summary>Decrypts and returns the plaintext boolean. Marks compromise.</summary>
    public bool ToInsecureBool() => ToInsecureValue();

    /// <summary>Compares two CyBool values (false &lt; true, consistent with .NET bool comparison).</summary>
    public int CompareTo(CyBool? other)
    {
        if (other is null) return 1;
        return DecryptValue().CompareTo(other.DecryptValue());
    }
}
