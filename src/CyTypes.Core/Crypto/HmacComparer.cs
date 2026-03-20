using System.Security.Cryptography;

namespace CyTypes.Core.Crypto;

/// <summary>
/// Utility for computing and verifying HMAC-SHA512 message authentication codes.
/// </summary>
public static class HmacComparer
{
    /// <summary>
    /// Computes an HMAC-SHA512 over the given data.
    /// </summary>
    /// <param name="key">The HMAC key.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <returns>The 64-byte HMAC-SHA512 result.</returns>
    public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        return HMACSHA512.HashData(key, data);
    }

    /// <summary>
    /// Verifies an HMAC-SHA512 using constant-time comparison.
    /// </summary>
    /// <param name="key">The HMAC key.</param>
    /// <param name="data">The data that was authenticated.</param>
    /// <param name="expectedMac">The expected HMAC value to compare against.</param>
    /// <returns><c>true</c> if the computed HMAC matches the expected value; otherwise <c>false</c>.</returns>
    public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> expectedMac)
    {
        var actual = Compute(key, data);
        return CryptographicOperations.FixedTimeEquals(actual, expectedMac);
    }
}
