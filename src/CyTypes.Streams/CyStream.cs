using System.Buffers.Binary;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Memory;

namespace CyTypes.Streams;

/// <summary>
/// A <see cref="Stream"/> wrapper that encrypts data on write and decrypts on read using
/// AES-256-GCM chunked encryption. All plaintext buffers are kept in <see cref="SecureBuffer"/>
/// and zeroed on disposal. The stream is sequential (<see cref="CanSeek"/> = false).
/// </summary>
public class CyStream : Stream, IAsyncDisposable
{
    private readonly Stream _innerStream;
    private readonly ChunkedCryptoEngine _engine;
    private readonly bool _isWriteMode;
    private readonly bool _leaveOpen;

    // Write state
    private SecureBuffer? _writeBuffer;
    private int _writeBufferPosition;
    private long _writeSequenceNumber;

    // Read state
    private SecureBuffer? _readBuffer;
    private int _readBufferPosition;
    private int _readBufferLength;
    private long _readSequenceNumber;
    private bool _readComplete;

    // Footer tracking (for write integrity)
    private readonly List<byte> _gcmTags = [];
    private byte[]? _headerBytes;
    private SecureBuffer? _streamKey;

    private bool _isDisposed;
    private bool _isFlushedFinal;

    /// <inheritdoc/>
    public override bool CanRead => !_isWriteMode && !_isDisposed;

    /// <inheritdoc/>
    public override bool CanSeek => false;

    /// <inheritdoc/>
    public override bool CanWrite => _isWriteMode && !_isDisposed;

    /// <inheritdoc/>
    public override long Length => throw new NotSupportedException("CyStream does not support Length.");

    /// <inheritdoc/>
    public override long Position
    {
        get => throw new NotSupportedException("CyStream does not support Position.");
        set => throw new NotSupportedException("CyStream does not support Position.");
    }

    /// <summary>
    /// Creates a new <see cref="CyStream"/> for writing encrypted data.
    /// </summary>
    /// <param name="innerStream">The underlying stream to write encrypted data to.</param>
    /// <param name="key">The 256-bit encryption key.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="chunkSize">The plaintext chunk size in bytes.</param>
    /// <param name="leaveOpen">Whether to leave the inner stream open on disposal.</param>
    /// <param name="flags">Optional stream flags.</param>
    public static CyStream CreateWriter(
        Stream innerStream,
        ReadOnlySpan<byte> key,
        Guid keyId,
        int chunkSize = 65536,
        bool leaveOpen = false,
        StreamSerializationFormat.StreamOption flags = StreamSerializationFormat.StreamOption.None)
    {
        return new CyStream(innerStream, key, keyId, chunkSize, isWriteMode: true, leaveOpen, flags);
    }

    /// <summary>
    /// Creates a new <see cref="CyStream"/> for reading encrypted data.
    /// </summary>
    /// <param name="innerStream">The underlying stream to read encrypted data from.</param>
    /// <param name="key">The 256-bit encryption key.</param>
    /// <param name="leaveOpen">Whether to leave the inner stream open on disposal.</param>
    public static CyStream CreateReader(
        Stream innerStream,
        ReadOnlySpan<byte> key,
        bool leaveOpen = false)
    {
        return new CyStream(innerStream, key, Guid.Empty, 0, isWriteMode: false, leaveOpen,
            StreamSerializationFormat.StreamOption.None);
    }

    private CyStream(
        Stream innerStream,
        ReadOnlySpan<byte> key,
        Guid keyId,
        int chunkSize,
        bool isWriteMode,
        bool leaveOpen,
        StreamSerializationFormat.StreamOption flags)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _isWriteMode = isWriteMode;
        _leaveOpen = leaveOpen;

        // Store key for HMAC
        _streamKey = new SecureBuffer(key.Length);
        _streamKey.Write(key);

        if (isWriteMode)
        {
            _engine = new ChunkedCryptoEngine(key, chunkSize);
            _writeBuffer = new SecureBuffer(chunkSize);
            _writeBufferPosition = 0;
            _writeSequenceNumber = 0;

            // Write header
            _headerBytes = new byte[StreamSerializationFormat.HeaderSize];
            StreamSerializationFormat.WriteHeader(_headerBytes, keyId, chunkSize, flags);
            _innerStream.Write(_headerBytes);
        }
        else
        {
            // Read header to determine chunk size
            _headerBytes = new byte[StreamSerializationFormat.HeaderSize];
            var bytesRead = ReadExactly(_innerStream, _headerBytes);
            if (bytesRead < StreamSerializationFormat.HeaderSize)
                throw new InvalidDataException("Stream is too short to contain a valid CyStream header.");

            var (_, readChunkSize, _) = StreamSerializationFormat.ReadHeader(_headerBytes);
            _engine = new ChunkedCryptoEngine(key, readChunkSize);
            _readSequenceNumber = 0;
            _readComplete = false;
        }
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (!_isWriteMode)
            throw new NotSupportedException("Stream is not in write mode.");
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (offset + count > buffer.Length)
            throw new ArgumentException("Offset and count exceed buffer length.");

        var remaining = count;
        var sourceOffset = offset;

        while (remaining > 0)
        {
            var spaceInBuffer = _engine.ChunkSize - _writeBufferPosition;
            var toCopy = Math.Min(remaining, spaceInBuffer);

            buffer.AsSpan(sourceOffset, toCopy).CopyTo(_writeBuffer!.AsSpan()[_writeBufferPosition..]);
            _writeBufferPosition += toCopy;
            sourceOffset += toCopy;
            remaining -= toCopy;

            // Buffer full — encrypt and write chunk
            if (_writeBufferPosition >= _engine.ChunkSize)
            {
                FlushChunk(isFinal: false);
            }
        }
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_isWriteMode)
            throw new NotSupportedException("Stream is not in read mode.");
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (offset + count > buffer.Length)
            throw new ArgumentException("Offset and count exceed buffer length.");

        var totalRead = 0;

        while (totalRead < count)
        {
            // If we have decrypted data in the buffer, copy it
            if (_readBuffer != null && _readBufferPosition < _readBufferLength)
            {
                var available = _readBufferLength - _readBufferPosition;
                var toCopy = Math.Min(count - totalRead, available);
                _readBuffer.AsReadOnlySpan().Slice(_readBufferPosition, toCopy)
                    .CopyTo(buffer.AsSpan(offset + totalRead));
                _readBufferPosition += toCopy;
                totalRead += toCopy;
                continue;
            }

            // Need more data — read and decrypt next chunk
            if (_readComplete)
                break;

            if (!ReadAndDecryptNextChunk())
                break;
        }

        return totalRead;
    }

    /// <inheritdoc/>
    public override void Flush()
    {
        if (_isWriteMode && !_isDisposed)
            _innerStream.Flush();
    }

    /// <summary>
    /// Finalizes the stream by writing the last chunk (with final marker) and the footer.
    /// This is called automatically on disposal.
    /// </summary>
    public void WriteFinal()
    {
        if (_isFlushedFinal || !_isWriteMode || _isDisposed)
            return;

        _isFlushedFinal = true;

        // Flush remaining data as final chunk
        FlushChunk(isFinal: true);

        // Write footer with HMAC
        var hmacKey = StreamSerializationFormat.DeriveHmacKey(_streamKey!.AsReadOnlySpan());
        try
        {
            // Authenticated data = header + all GCM tags
            var authData = new byte[_headerBytes!.Length + _gcmTags.Count];
            _headerBytes.CopyTo(authData, 0);
            _gcmTags.CopyTo(authData, _headerBytes.Length);

            var footer = new byte[StreamSerializationFormat.FooterSize];
            StreamSerializationFormat.WriteFooter(footer, _writeSequenceNumber, hmacKey, authData);
            _innerStream.Write(footer);
            _innerStream.Flush();

            CryptographicOperations.ZeroMemory(authData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hmacKey);
        }
    }

    private void FlushChunk(bool isFinal)
    {
        if (_writeBufferPosition == 0 && !isFinal) return;

        var plaintext = _writeBuffer!.AsReadOnlySpan()[.._writeBufferPosition];
        var encrypted = _engine.EncryptChunk(plaintext, _writeSequenceNumber, isFinal);

        // Store GCM tag (last 16 bytes of encrypted chunk)
        var tag = encrypted.AsSpan(encrypted.Length - 16, 16);
        foreach (var b in tag) _gcmTags.Add(b);

        // Write chunk length prefix + encrypted data
        Span<byte> lengthPrefix = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(lengthPrefix, encrypted.Length);
        _innerStream.Write(lengthPrefix);
        _innerStream.Write(encrypted);

        _writeSequenceNumber++;
        _writeBufferPosition = 0;

        // Zero the write buffer
        CryptographicOperations.ZeroMemory(_writeBuffer.AsSpan());
    }

    private bool ReadAndDecryptNextChunk()
    {
        // Read chunk length prefix
        Span<byte> lengthBuf = stackalloc byte[4];
        if (ReadExactly(_innerStream, lengthBuf) < 4)
            return false;

        var chunkLength = BinaryPrimitives.ReadInt32BigEndian(lengthBuf);
        if (chunkLength <= 0 || chunkLength > _engine.ChunkSize + 36 + 4)
            return false; // Invalid or this might be the footer

        var encryptedChunk = new byte[chunkLength];
        if (ReadExactly(_innerStream, encryptedChunk) < chunkLength)
            throw new InvalidDataException("Stream truncated: incomplete chunk data.");

        var plaintext = _engine.DecryptChunk(encryptedChunk, _readSequenceNumber, out var isFinal);

        // Dispose old read buffer and set new one
        _readBuffer?.Dispose();
        _readBuffer = new SecureBuffer(plaintext.Length > 0 ? plaintext.Length : 1);
        if (plaintext.Length > 0)
            _readBuffer.Write(plaintext);
        _readBufferPosition = 0;
        _readBufferLength = plaintext.Length;

        CryptographicOperations.ZeroMemory(plaintext);
        _readSequenceNumber++;

        if (isFinal)
            _readComplete = true;

        return plaintext.Length > 0;
    }

    private static int ReadExactly(Stream stream, Span<byte> buffer)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var bytesRead = stream.Read(buffer[totalRead..]);
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }
        return totalRead;
    }

    /// <inheritdoc/>
    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException("CyStream does not support seeking.");

    /// <inheritdoc/>
    public override void SetLength(long value) =>
        throw new NotSupportedException("CyStream does not support SetLength.");

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (_isDisposed) return;

        if (disposing)
        {
            if (_isWriteMode)
                WriteFinal();

            _isDisposed = true;

            _writeBuffer?.Dispose();
            _readBuffer?.Dispose();
            _engine.Dispose();

            _streamKey?.Dispose();
            _streamKey = null;

            // Zero GCM tags (crypto material)
            for (var i = 0; i < _gcmTags.Count; i++) _gcmTags[i] = 0;
            _gcmTags.Clear();

            if (!_leaveOpen)
                _innerStream.Dispose();
        }
        else
        {
            _isDisposed = true;
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        if (_isDisposed) return;

        if (_isWriteMode)
            WriteFinal();

        _isDisposed = true;

        _writeBuffer?.Dispose();
        _readBuffer?.Dispose();
        _engine.Dispose();

        _streamKey?.Dispose();
        _streamKey = null;

        // Zero GCM tags (crypto material)
        for (var i = 0; i < _gcmTags.Count; i++) _gcmTags[i] = 0;
        _gcmTags.Clear();

        if (!_leaveOpen)
            await _innerStream.DisposeAsync().ConfigureAwait(false);

        GC.SuppressFinalize(this);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
