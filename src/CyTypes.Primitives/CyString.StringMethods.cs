using System.Security.Cryptography;
using System.Text;
using CyTypes.Core.Policy;

namespace CyTypes.Primitives;

/// <summary>
/// String manipulation methods. All operate via secure enclave:
/// decrypt → pinned buffer → compute → re-encrypt → zero intermediates.
/// </summary>
public sealed partial class CyString
{
    // === String Methods (return CyString, operate in enclave) ===

    /// <summary>Returns a substring starting at the specified index.</summary>
    public CyString Substring(int startIndex) => EnclaveOp(s => s.Substring(startIndex));
    /// <summary>Returns a substring starting at the specified index with the given length.</summary>
    public CyString Substring(int startIndex, int length) => EnclaveOp(s => s.Substring(startIndex, length));
    /// <summary>Removes leading and trailing whitespace.</summary>
    public CyString Trim() => EnclaveOp(s => s.Trim());
    /// <summary>Removes leading whitespace.</summary>
    public CyString TrimStart() => EnclaveOp(s => s.TrimStart());
    /// <summary>Removes trailing whitespace.</summary>
    public CyString TrimEnd() => EnclaveOp(s => s.TrimEnd());
    /// <summary>Converts the string to upper-case using invariant culture.</summary>
    public CyString ToUpper() => EnclaveOp(s => s.ToUpperInvariant());
    /// <summary>Converts the string to lower-case using invariant culture.</summary>
    public CyString ToLower() => EnclaveOp(s => s.ToLowerInvariant());
    /// <summary>Converts the string to upper-case using invariant culture.</summary>
    public CyString ToUpperInvariant() => EnclaveOp(s => s.ToUpperInvariant());
    /// <summary>Converts the string to lower-case using invariant culture.</summary>
    public CyString ToLowerInvariant() => EnclaveOp(s => s.ToLowerInvariant());
    /// <summary>Replaces all occurrences of a specified string with another string.</summary>
    public CyString Replace(string oldValue, string newValue) => EnclaveOp(s => s.Replace(oldValue, newValue));
    /// <summary>Inserts a string at the specified index.</summary>
    public CyString Insert(int startIndex, string value) => EnclaveOp(s => s.Insert(startIndex, value));
    /// <summary>Removes all characters from the specified index to the end.</summary>
    public CyString Remove(int startIndex) => EnclaveOp(s => s.Remove(startIndex));
    /// <summary>Removes the specified number of characters starting at the given index.</summary>
    public CyString Remove(int startIndex, int count) => EnclaveOp(s => s.Remove(startIndex, count));
    /// <summary>Pads the string on the left to the specified total width.</summary>
    public CyString PadLeft(int totalWidth) => EnclaveOp(s => s.PadLeft(totalWidth));
    /// <summary>Pads the string on the left with the specified character to the given total width.</summary>
    public CyString PadLeft(int totalWidth, char paddingChar) => EnclaveOp(s => s.PadLeft(totalWidth, paddingChar));
    /// <summary>Pads the string on the right to the specified total width.</summary>
    public CyString PadRight(int totalWidth) => EnclaveOp(s => s.PadRight(totalWidth));
    /// <summary>Pads the string on the right with the specified character to the given total width.</summary>
    public CyString PadRight(int totalWidth, char paddingChar) => EnclaveOp(s => s.PadRight(totalWidth, paddingChar));

    // === Methods returning bool/int (operate in enclave, don't mark compromise) ===

    /// <summary>Returns true if the string contains the specified value (ordinal comparison).</summary>
    public bool Contains(string value) => EnclaveQuery(s => s.Contains(value, StringComparison.Ordinal));
    /// <summary>Returns true if the string contains the specified value using the given comparison type.</summary>
    public bool Contains(string value, StringComparison comparisonType) => EnclaveQuery(s => s.Contains(value, comparisonType));
    /// <summary>Returns true if the string starts with the specified value (ordinal comparison).</summary>
    public bool StartsWith(string value) => EnclaveQuery(s => s.StartsWith(value, StringComparison.Ordinal));
    /// <summary>Returns true if the string starts with the specified value using the given comparison type.</summary>
    public bool StartsWith(string value, StringComparison comparisonType) => EnclaveQuery(s => s.StartsWith(value, comparisonType));
    /// <summary>Returns true if the string ends with the specified value (ordinal comparison).</summary>
    public bool EndsWith(string value) => EnclaveQuery(s => s.EndsWith(value, StringComparison.Ordinal));
    /// <summary>Returns true if the string ends with the specified value using the given comparison type.</summary>
    public bool EndsWith(string value, StringComparison comparisonType) => EnclaveQuery(s => s.EndsWith(value, comparisonType));
    /// <summary>Returns the zero-based index of the first occurrence of the specified value.</summary>
    public int IndexOf(string value) => EnclaveQuery(s => s.IndexOf(value, StringComparison.Ordinal));
    /// <summary>Returns the zero-based index of the first occurrence using the given comparison type.</summary>
    public int IndexOf(string value, StringComparison comparisonType) => EnclaveQuery(s => s.IndexOf(value, comparisonType));
    /// <summary>Returns the zero-based index of the last occurrence of the specified value.</summary>
    public int LastIndexOf(string value) => EnclaveQuery(s => s.LastIndexOf(value, StringComparison.Ordinal));
    /// <summary>Returns the zero-based index of the last occurrence using the given comparison type.</summary>
    public int LastIndexOf(string value, StringComparison comparisonType) => EnclaveQuery(s => s.LastIndexOf(value, comparisonType));
    /// <summary>Returns true if the string is null or empty.</summary>
    public bool IsNullOrEmpty() => EnclaveQuery(string.IsNullOrEmpty);
    /// <summary>Returns true if the string is null, empty, or consists only of whitespace.</summary>
    public bool IsNullOrWhiteSpace() => EnclaveQuery(string.IsNullOrWhiteSpace);

    // === Methods returning CyString[] ===

    /// <summary>Splits the string by the specified separator character.</summary>
    public CyString[] Split(char separator)
    {
        var plain = DecryptValue();
        var parts = plain.Split(separator);
        var taint = IsCompromised || IsTainted;
        var results = new CyString[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            results[i] = new CyString(parts[i], Policy);
            if (taint) results[i].MarkTainted();
        }
        return results;
    }

    /// <summary>Splits the string by any of the specified separator characters.</summary>
    public CyString[] Split(char[] separators)
    {
        var plain = DecryptValue();
        var parts = plain.Split(separators);
        var taint = IsCompromised || IsTainted;
        var results = new CyString[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            results[i] = new CyString(parts[i], Policy);
            if (taint) results[i].MarkTainted();
        }
        return results;
    }

    // === Static Methods ===

    /// <summary>Concatenates two CyString instances.</summary>
    public static CyString Concat(CyString a, CyString b) => a + b;

    /// <summary>Joins multiple CyString values with the specified separator.</summary>
    public static CyString Join(string separator, params CyString[] values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Length == 0) return new CyString("");

        var policy = values[0].Policy;
        var taint = false;
        var parts = new string[values.Length];
        for (var i = 0; i < values.Length; i++)
        {
            policy = PolicyResolver.Resolve(policy, values[i].Policy, allowStrictCrossPolicy: true);
            if (values[i].IsCompromised || values[i].IsTainted) taint = true;
            parts[i] = values[i].DecryptValue();
        }

        var result = new CyString(string.Join(separator, parts), policy);
        if (taint) result.MarkTainted();
        return result;
    }

    // === Secure Methods (HMAC-based, no compromise marking) ===

    /// <summary>
    /// Compares equality without marking compromise.
    /// Uses pinned temp buffer for comparison, then zeros.
    /// </summary>
    public bool SecureEquals(CyString other)
    {
        ArgumentNullException.ThrowIfNull(other);

        // SECURITY: Constant-time comparison on UTF-8 bytes to prevent timing attacks.
        // Length check is deliberately NOT used as early-exit — it would leak length info.
        byte[] bytesA = Encoding.UTF8.GetBytes(DecryptValue());
        byte[] bytesB = Encoding.UTF8.GetBytes(other.DecryptValue());
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

    /// <summary>Checks if this string contains the value without marking compromise.</summary>
    public bool SecureContains(string value) => EnclaveQuery(s => s.Contains(value, StringComparison.Ordinal));

    /// <summary>Checks if this string starts with the value without marking compromise.</summary>
    public bool SecureStartsWith(string value) => EnclaveQuery(s => s.StartsWith(value, StringComparison.Ordinal));

    /// <summary>Checks if this string ends with the value without marking compromise.</summary>
    public bool SecureEndsWith(string value) => EnclaveQuery(s => s.EndsWith(value, StringComparison.Ordinal));

    // === Internal Helpers ===

    /// <summary>
    /// Decrypt → apply function → re-encrypt result → return new CyString.
    /// Taint propagates from this instance to result.
    /// </summary>
    private CyString EnclaveOp(Func<string, string> operation)
    {
        var plain = DecryptValue();
        var transformed = operation(plain);
        var result = new CyString(transformed, Policy);
        if (IsCompromised || IsTainted) result.MarkTainted();
        return result;
    }

    /// <summary>
    /// Decrypt → query → return scalar. Does NOT mark compromise since
    /// only a boolean/int is returned, not the plaintext itself.
    /// </summary>
    private T EnclaveQuery<T>(Func<string, T> query)
    {
        var plain = DecryptValue();
        return query(plain);
    }
}
