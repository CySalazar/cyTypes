using System.Buffers.Binary;
using System.Security.Cryptography;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Memory;

namespace CyTypes.Core.Crypto;

/// <summary>
/// AES-256-GCM chunked encryption engine for streaming.
/// Chunk layout: [seqNumber:8 big-endian][nonce:12][ciphertext:N][gcmTag:16].
/// The high bit of the sequence number marks the final chunk (anti-truncation).
/// Key ratcheting via HKDF occurs every 2^20 chunks to prevent nonce reuse.
/// </summary>
public sealed class ChunkedCryptoEngine : IStreamCryptoEngine, IDisposable
{
    private const int SequenceNumberSize = 8;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int ChunkOverhead = SequenceNumberSize + NonceSize + TagSize;
    private const long FinalChunkMarker = unchecked((long)(1UL << 63));
    private const long RatchetInterval = 1L << 20; // Key ratcheting every ~1M chunks

    private static readonly byte[] RatchetInfo = "CyTypes.KeyRatchet"u8.ToArray();

    private const int MaxChunkSize = 16 * 1024 * 1024; // 16 MB

    private SecureBuffer _currentKey;
    private long _ratchetGeneration;
    private int _isDisposed; // 0 = alive, 1 = disposed (atomic via Interlocked)

    /// <inheritdoc/>
    public int ChunkSize { get; }

    /// <summary>
    /// Initializes a new <see cref="ChunkedCryptoEngine"/> with the specified key and chunk size.
    /// </summary>
    /// <param name="key">The 256-bit encryption key.</param>
    /// <param name="chunkSize">The plaintext chunk size in bytes. Default is 65536 (64 KB).</param>
    public ChunkedCryptoEngine(ReadOnlySpan<byte> key, int chunkSize = 65536)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(chunkSize, 0);
        if (chunkSize > MaxChunkSize)
            throw new ArgumentOutOfRangeException(nameof(chunkSize), $"Chunk size must not exceed {MaxChunkSize} bytes (16 MB).");
        if (key.Length != 32)
            throw new ArgumentException("Key must be 256 bits (32 bytes).", nameof(key));

        ChunkSize = chunkSize;
        _currentKey = new SecureBuffer(32);
        _currentKey.Write(key);
    }

    /// <inheritdoc/>
    public byte[] EncryptChunk(ReadOnlySpan<byte> plaintext, long sequenceNumber, bool isFinal)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        if (sequenceNumber < 0)
            throw new CryptographicException("Sequence number overflow: maximum chunk count exceeded.");
        RatchetKeyIfNeeded(sequenceNumber);

        var encodedSeq = isFinal ? (sequenceNumber | FinalChunkMarker) : sequenceNumber;

        // Build AAD from sequence number (prevents reordering)
        Span<byte> aad = stackalloc byte[SequenceNumberSize];
        BinaryPrimitives.WriteInt64BigEndian(aad, encodedSeq);

        // Output: [seqNumber:8][nonce:12][ciphertext:N][tag:16]
        var outputLength = ChunkOverhead + plaintext.Length;
        var output = new byte[outputLength];

        // Write sequence number
        BinaryPrimitives.WriteInt64BigEndian(output.AsSpan(0, SequenceNumberSize), encodedSeq);

        // Generate random nonce
        var nonce = output.AsSpan(SequenceNumberSize, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        // Encrypt
        var ciphertext = output.AsSpan(SequenceNumberSize + NonceSize, plaintext.Length);
        var tag = output.AsSpan(SequenceNumberSize + NonceSize + plaintext.Length, TagSize);

        using var aes = new AesGcm(_currentKey.AsReadOnlySpan(), TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return output;
    }

    /// <inheritdoc/>
    public byte[] DecryptChunk(ReadOnlySpan<byte> encryptedChunk, long expectedSequenceNumber, out bool isFinal)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);

        if (encryptedChunk.Length < ChunkOverhead)
            throw new CryptographicException("Encrypted chunk is too short.");

        // Read and verify sequence number
        var encodedSeq = BinaryPrimitives.ReadInt64BigEndian(encryptedChunk[..SequenceNumberSize]);
        isFinal = (encodedSeq & FinalChunkMarker) != 0;
        var actualSeq = encodedSeq & ~FinalChunkMarker;

        if (actualSeq != expectedSequenceNumber)
            throw new CryptographicException(
                $"Chunk sequence number mismatch. Expected {expectedSequenceNumber}, got {actualSeq}.");

        RatchetKeyIfNeeded(expectedSequenceNumber);

        // Build AAD
        Span<byte> aad = stackalloc byte[SequenceNumberSize];
        BinaryPrimitives.WriteInt64BigEndian(aad, encodedSeq);

        // Extract components
        var nonce = encryptedChunk.Slice(SequenceNumberSize, NonceSize);
        var ciphertextLength = encryptedChunk.Length - ChunkOverhead;
        var ciphertext = encryptedChunk.Slice(SequenceNumberSize + NonceSize, ciphertextLength);
        var tag = encryptedChunk[^TagSize..];

        var plaintext = new byte[ciphertextLength];

        using var aes = new AesGcm(_currentKey.AsReadOnlySpan(), TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);

        return plaintext;
    }

    /// <summary>
    /// Gets the total size of an encrypted chunk given a plaintext size.
    /// </summary>
    public static int GetEncryptedChunkSize(int plaintextSize) => plaintextSize + ChunkOverhead;

    private void RatchetKeyIfNeeded(long sequenceNumber)
    {
        var generation = sequenceNumber / RatchetInterval;
        if (generation <= _ratchetGeneration) return;

        // Derive new key via HKDF for each generation step
        while (_ratchetGeneration < generation)
        {
            _ratchetGeneration++;
            var salt = new byte[8];
            BinaryPrimitives.WriteInt64BigEndian(salt, _ratchetGeneration);

            var newKeyBytes = HkdfKeyDerivation.DeriveKey(
                _currentKey.AsReadOnlySpan(),
                outputLength: 32,
                salt: salt,
                info: RatchetInfo);

            var newKey = new SecureBuffer(32);
            newKey.Write(newKeyBytes);
            CryptographicOperations.ZeroMemory(newKeyBytes);

            var old = _currentKey;
            _currentKey = newKey;
            old.Dispose();
        }
    }

    /// <summary>Disposes the engine and zeros the key material.</summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;
        _currentKey.Dispose();
    }
}
