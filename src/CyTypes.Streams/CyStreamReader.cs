using System.Buffers.Binary;

namespace CyTypes.Streams;

/// <summary>
/// Reads framed CyType values from a <see cref="CyStream"/>.
/// Each frame: [typeId:2][payloadLength:4][encryptedPayload:N].
/// </summary>
public sealed class CyStreamReader : IDisposable
{
    private readonly CyStream _stream;
    private readonly bool _leaveOpen;
    private int _isDisposed; // 0 = alive, 1 = disposed (atomic via Interlocked)

    /// <summary>
    /// Initializes a new <see cref="CyStreamReader"/> that reads from the given <see cref="CyStream"/>.
    /// </summary>
    /// <param name="stream">The encrypted stream to read from.</param>
    /// <param name="leaveOpen">Whether to leave the stream open on disposal.</param>
    public CyStreamReader(CyStream stream, bool leaveOpen = false)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _leaveOpen = leaveOpen;
    }

    /// <summary>
    /// Reads the next framed value from the stream.
    /// </summary>
    /// <returns>The type ID and encrypted payload, or <c>null</c> if the stream is exhausted.</returns>
    public (ushort TypeId, byte[] EncryptedPayload)? ReadNext()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);

        // Read frame header
        var header = new byte[6];
        var bytesRead = ReadExactly(header);
        if (bytesRead == 0)
            return null;
        if (bytesRead < 6)
            throw new InvalidDataException("Stream truncated: incomplete frame header.");

        var typeId = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(0, 2));
        var payloadLength = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(2, 4));

        if (payloadLength < 0 || payloadLength > 16 * 1024 * 1024)
            throw new InvalidDataException($"Invalid payload length: {payloadLength}.");

        var payload = new byte[payloadLength];
        bytesRead = ReadExactly(payload);
        if (bytesRead < payloadLength)
            throw new InvalidDataException("Stream truncated: incomplete frame payload.");

        return (typeId, payload);
    }

    /// <summary>
    /// Reads all remaining framed values from the stream.
    /// </summary>
    public IEnumerable<(ushort TypeId, byte[] EncryptedPayload)> ReadAll()
    {
        while (true)
        {
            var result = ReadNext();
            if (result == null) yield break;
            yield return result.Value;
        }
    }

    private int ReadExactly(byte[] buffer)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = _stream.Read(buffer, totalRead, buffer.Length - totalRead);
            if (read == 0) break;
            totalRead += read;
        }
        return totalRead;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        if (!_leaveOpen)
            _stream.Dispose();
    }
}
