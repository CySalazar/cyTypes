namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Defines chunked encryption and decryption operations for streaming scenarios.
/// Each chunk is independently authenticated with AES-256-GCM and carries a sequence number
/// to prevent reordering and truncation attacks.
/// </summary>
public interface IStreamCryptoEngine
{
    /// <summary>Gets the plaintext chunk size in bytes.</summary>
    int ChunkSize { get; }

    /// <summary>
    /// Encrypts a single chunk of plaintext.
    /// </summary>
    /// <param name="plaintext">The plaintext data for this chunk.</param>
    /// <param name="sequenceNumber">The zero-based sequence number of this chunk.</param>
    /// <param name="isFinal">Whether this is the last chunk in the stream.</param>
    /// <returns>The encrypted chunk bytes.</returns>
    byte[] EncryptChunk(ReadOnlySpan<byte> plaintext, long sequenceNumber, bool isFinal);

    /// <summary>
    /// Decrypts a single encrypted chunk and verifies its sequence number and authentication tag.
    /// </summary>
    /// <param name="encryptedChunk">The encrypted chunk data.</param>
    /// <param name="expectedSequenceNumber">The expected sequence number for ordering verification.</param>
    /// <param name="isFinal">Set to <c>true</c> if this chunk is marked as the final chunk.</param>
    /// <returns>The decrypted plaintext.</returns>
    byte[] DecryptChunk(ReadOnlySpan<byte> encryptedChunk, long expectedSequenceNumber, out bool isFinal);
}
