namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Provides homomorphic comparison operations by computing encrypted differences
/// and extracting comparison results at decryption time.
/// </summary>
public interface IFheComparisonEngine
{
    /// <summary>
    /// Computes the encrypted difference (a - b) for deferred sign extraction.
    /// The result remains encrypted until <see cref="DecryptComparison"/> is called.
    /// </summary>
    byte[] ComputeDifference(byte[] a, byte[] b);

    /// <summary>
    /// Decrypts an encrypted difference and returns the comparison result.
    /// </summary>
    /// <returns>-1 if a &lt; b, 0 if equal, +1 if a &gt; b.</returns>
    int DecryptComparison(byte[] encryptedDifference);

    /// <summary>
    /// Decrypts an encrypted difference and checks equality within the specified tolerance.
    /// </summary>
    /// <param name="encryptedDifference">The encrypted difference ciphertext.</param>
    /// <param name="epsilon">Tolerance for approximate equality (0.0 for exact, positive for CKKS).</param>
    /// <returns>True if the values are equal within the tolerance.</returns>
    bool DecryptEquality(byte[] encryptedDifference, double epsilon = 0.0);
}
