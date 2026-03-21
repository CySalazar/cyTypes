using System.Security.Cryptography;
using System.Text;
using CyTypes.Core.Policy;

namespace CyTypes.Primitives;

public sealed partial class CyString
{
    /// <summary>Encrypts a native string into a CyString (safe, uses Balanced policy).</summary>
    public static implicit operator CyString(string value) => new(value);

    /// <summary>Decrypts the CyString to a native string. Marks compromise.</summary>
    public static explicit operator string(CyString cy) => cy.ToInsecureString();

    /// <summary>Concatenation operator. Operates in secure enclave.</summary>
    public static CyString operator +(CyString left, CyString right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var resolved = PolicyResolver.Resolve(left.Policy, right.Policy, allowStrictCrossPolicy: true);
        var taint = left.IsCompromised || left.IsTainted || right.IsCompromised || right.IsTainted;

        var leftVal = left.DecryptValue();
        var rightVal = right.DecryptValue();
        var result = new CyString(leftVal + rightVal, resolved);

        if (taint) result.MarkTainted();
        return result;
    }

    /// <summary>
    /// Constant-time equality operator. Uses <see cref="CryptographicOperations.FixedTimeEquals"/>
    /// to prevent timing side-channel attacks. Does not early-exit on length difference.
    /// </summary>
    public static bool operator ==(CyString? left, CyString? right)
    {
        if (left is null && right is null) return true;
        if (left is null || right is null) return false;

        // SECURITY: Use constant-time comparison on UTF-8 bytes.
        // No early-exit on Length — that would leak length information.
        byte[] bytesA = Encoding.UTF8.GetBytes(left.DecryptValue());
        byte[] bytesB = Encoding.UTF8.GetBytes(right.DecryptValue());
        try
        {
            return CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytesA);
            CryptographicOperations.ZeroMemory(bytesB);
        }
    }

    /// <summary>Inequality operator. Delegates to the constant-time equality operator.</summary>
    public static bool operator !=(CyString? left, CyString? right) => !(left == right);

    /// <summary>Less-than comparison using ordinal string comparison.</summary>
    public static bool operator <(CyString left, CyString right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) < 0;
    }

    /// <summary>Greater-than comparison using ordinal string comparison.</summary>
    public static bool operator >(CyString left, CyString right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) > 0;
    }

    /// <summary>Less-than-or-equal comparison using ordinal string comparison.</summary>
    public static bool operator <=(CyString left, CyString right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) <= 0;
    }

    /// <summary>Greater-than-or-equal comparison using ordinal string comparison.</summary>
    public static bool operator >=(CyString left, CyString right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        return left.CompareTo(right) >= 0;
    }

    /// <summary>
    /// Character indexer. Security behavior depends on <see cref="CyTypes.Core.Policy.Components.CharAccessMode"/>:
    /// <see cref="CyTypes.Core.Policy.Components.CharAccessMode.CompromiseOnAccess"/> marks compromise,
    /// <see cref="CyTypes.Core.Policy.Components.CharAccessMode.TaintOnAccess"/> marks taint only.
    /// </summary>
    public char this[int index]
    {
        get
        {
            if (Policy.CharAccess == CyTypes.Core.Policy.Components.CharAccessMode.TaintOnAccess)
                MarkTainted();
            else
                MarkCompromised();
            var plain = DecryptValue();
            return plain[index];
        }
    }

    /// <inheritdoc/>
    public bool Equals(CyString? other) => other is not null && this == other;
    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CyString);
    /// <summary>
    /// Returns a hash code based on this instance's unique identity (InstanceId), NOT on the encrypted value.
    /// Two instances with the same plaintext will have different hash codes.
    /// Do not use CyType instances as dictionary keys or HashSet elements.
    /// </summary>
    public override int GetHashCode() => InstanceId.GetHashCode();
}
