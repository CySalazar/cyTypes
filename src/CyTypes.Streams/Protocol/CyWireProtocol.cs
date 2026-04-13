using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CyTypes.Streams.Protocol;

/// <summary>
/// Wire protocol for CyStream IPC and network transports.
/// Frame layout: [frameType:1][flags:1][payloadLength:4][payload:N].
/// Authenticated frames append: [hmac-sha256:32] after payload.
/// </summary>
public static class CyWireProtocol
{
    /// <summary>Frame header size in bytes.</summary>
    public const int FrameHeaderSize = 6;

    /// <summary>Maximum payload size (16 MB).</summary>
    public const int MaxPayloadSize = 16 * 1024 * 1024;

    /// <summary>HMAC-SHA256 tag size for authenticated frames.</summary>
    public const int HmacSize = 32;

    /// <summary>
    /// Writes a frame to the stream.
    /// </summary>
    public static void WriteFrame(Stream stream, FrameType type, ReadOnlySpan<byte> payload, FrameFlags flags = FrameFlags.None)
    {
        Span<byte> header = stackalloc byte[FrameHeaderSize];
        header[0] = (byte)type;
        header[1] = (byte)flags;
        BinaryPrimitives.WriteInt32BigEndian(header[2..], payload.Length);

        stream.Write(header);
        if (payload.Length > 0)
            stream.Write(payload);
        stream.Flush();
    }

    /// <summary>
    /// Writes a frame to the stream asynchronously.
    /// </summary>
    public static async Task WriteFrameAsync(
        Stream stream, FrameType type, ReadOnlyMemory<byte> payload,
        FrameFlags flags = FrameFlags.None, CancellationToken ct = default)
    {
        var header = new byte[FrameHeaderSize];
        header[0] = (byte)type;
        header[1] = (byte)flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(2), payload.Length);

        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        if (payload.Length > 0)
            await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads a frame from the stream.
    /// </summary>
    /// <returns>The frame, or <c>null</c> if the stream is closed.</returns>
    public static Frame? ReadFrame(Stream stream)
    {
        Span<byte> header = stackalloc byte[FrameHeaderSize];
        var read = ReadExactly(stream, header);
        if (read == 0) return null;
        if (read < FrameHeaderSize)
            throw new InvalidDataException("Incomplete frame header.");

        var type = (FrameType)header[0];
        if (!Enum.IsDefined(type))
            throw new InvalidDataException($"Unknown frame type: 0x{header[0]:X2}.");
        var flags = (FrameFlags)header[1];
        var payloadLength = BinaryPrimitives.ReadInt32BigEndian(header[2..]);

        if (payloadLength < 0 || payloadLength > MaxPayloadSize)
            throw new InvalidDataException($"Invalid payload length: {payloadLength}.");

        byte[] payload;
        if (payloadLength > 0)
        {
            payload = new byte[payloadLength];
            var payloadRead = ReadExactly(stream, payload);
            if (payloadRead < payloadLength)
                throw new InvalidDataException("Incomplete frame payload.");
        }
        else
        {
            payload = [];
        }

        return new Frame(type, flags, payload);
    }

    /// <summary>
    /// Reads a frame from the stream asynchronously.
    /// </summary>
    public static async Task<Frame?> ReadFrameAsync(Stream stream, CancellationToken ct = default)
    {
        var header = new byte[FrameHeaderSize];
        var read = await ReadExactlyAsync(stream, header, ct).ConfigureAwait(false);
        if (read == 0) return null;
        if (read < FrameHeaderSize)
            throw new InvalidDataException("Incomplete frame header.");

        var type = (FrameType)header[0];
        if (!Enum.IsDefined(type))
            throw new InvalidDataException($"Unknown frame type: 0x{header[0]:X2}.");
        var flags = (FrameFlags)header[1];
        var payloadLength = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(2));

        if (payloadLength < 0 || payloadLength > MaxPayloadSize)
            throw new InvalidDataException($"Invalid payload length: {payloadLength}.");

        byte[] payload;
        if (payloadLength > 0)
        {
            payload = new byte[payloadLength];
            var payloadRead = await ReadExactlyAsync(stream, payload, ct).ConfigureAwait(false);
            if (payloadRead < payloadLength)
                throw new InvalidDataException("Incomplete frame payload.");
        }
        else
        {
            payload = [];
        }

        return new Frame(type, flags, payload);
    }

    private static int ReadExactly(Stream stream, Span<byte> buffer)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var n = stream.Read(buffer[totalRead..]);
            if (n == 0) break;
            totalRead += n;
        }
        return totalRead;
    }

    /// <summary>Writes an authenticated frame: header + payload + HMAC-SHA256 over (header || payload).</summary>
    public static Task WriteAuthenticatedFrameAsync(
        Stream stream, FrameType type, ReadOnlyMemory<byte> payload,
        ReadOnlySpan<byte> hmacKey, FrameFlags flags = FrameFlags.None,
        CancellationToken ct = default)
    {
        flags |= FrameFlags.Authenticated;
        var header = new byte[FrameHeaderSize];
        header[0] = (byte)type;
        header[1] = (byte)flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(2), payload.Length);

        // Compute HMAC-SHA256 synchronously (before entering async state machine) so we can use Span
        var authData = new byte[FrameHeaderSize + payload.Length];
        header.CopyTo(authData, 0);
        payload.Span.CopyTo(authData.AsSpan(FrameHeaderSize));
        var hmac = HMACSHA256.HashData(hmacKey, authData);
        CryptographicOperations.ZeroMemory(authData);

        return WriteAuthenticatedFrameCoreAsync(stream, header, payload, hmac, ct);
    }

    private static async Task WriteAuthenticatedFrameCoreAsync(
        Stream stream, byte[] header, ReadOnlyMemory<byte> payload, byte[] hmac,
        CancellationToken ct)
    {
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        if (payload.Length > 0)
            await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.WriteAsync(hmac, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Reads a frame and verifies HMAC-SHA256 if the Authenticated flag is set.</summary>
    public static Task<Frame?> ReadAuthenticatedFrameAsync(
        Stream stream, ReadOnlySpan<byte> hmacKey, CancellationToken ct = default)
    {
        // Copy the key before entering the async state machine (Span cannot cross awaits in .NET 8)
        var keyCopy = hmacKey.ToArray();
        return ReadAuthenticatedFrameCoreAsync(stream, keyCopy, ct);
    }

    private static async Task<Frame?> ReadAuthenticatedFrameCoreAsync(
        Stream stream, byte[] hmacKey, CancellationToken ct)
    {
        try
        {
            var header = new byte[FrameHeaderSize];
            var read = await ReadExactlyAsync(stream, header, ct).ConfigureAwait(false);
            if (read == 0) return null;
            if (read < FrameHeaderSize)
                throw new InvalidDataException("Incomplete frame header.");

            var type = (FrameType)header[0];
            if (!Enum.IsDefined(type))
                throw new InvalidDataException($"Unknown frame type: 0x{header[0]:X2}.");
            var flags = (FrameFlags)header[1];
            var payloadLength = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(2));

            if (payloadLength < 0 || payloadLength > MaxPayloadSize)
                throw new InvalidDataException($"Invalid payload length: {payloadLength}.");

            var payload = payloadLength > 0 ? new byte[payloadLength] : Array.Empty<byte>();
            if (payloadLength > 0)
            {
                var payloadRead = await ReadExactlyAsync(stream, payload, ct).ConfigureAwait(false);
                if (payloadRead < payloadLength)
                    throw new InvalidDataException("Incomplete frame payload.");
            }

            if ((flags & FrameFlags.Authenticated) != 0)
            {
                var receivedHmac = new byte[HmacSize];
                var hmacRead = await ReadExactlyAsync(stream, receivedHmac, ct).ConfigureAwait(false);
                if (hmacRead < HmacSize)
                    throw new InvalidDataException("Incomplete frame HMAC.");

                var authData = new byte[FrameHeaderSize + payloadLength];
                header.CopyTo(authData, 0);
                if (payloadLength > 0)
                    payload.CopyTo(authData, FrameHeaderSize);

                var expectedHmac = HMACSHA256.HashData(hmacKey, authData);
                if (!CryptographicOperations.FixedTimeEquals(receivedHmac, expectedHmac))
                    throw new CryptographicException("Frame HMAC verification failed. The frame may have been tampered with.");

                CryptographicOperations.ZeroMemory(authData);
            }

            return new Frame(type, flags, payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hmacKey);
        }
    }

    private static async Task<int> ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer[totalRead..], ct).ConfigureAwait(false);
            if (n == 0) break;
            totalRead += n;
        }
        return totalRead;
    }
}

/// <summary>Identifies the type of wire protocol frame.</summary>
public enum FrameType : byte
{
    /// <summary>Key exchange handshake frame.</summary>
    Handshake = 0x01,
    /// <summary>Encrypted data frame.</summary>
    Data = 0x02,
    /// <summary>Connection heartbeat frame.</summary>
    Heartbeat = 0x03,
    /// <summary>Graceful close frame.</summary>
    Close = 0x04,
    /// <summary>Error frame.</summary>
    Error = 0x05
}

/// <summary>Frame flags.</summary>
[Flags]
public enum FrameFlags : byte
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>Frame contains the ML-KEM ciphertext (initiator handshake response).</summary>
    HandshakeResponse = 1,
    /// <summary>Frame is compressed.</summary>
    Compressed = 2,
    /// <summary>Handshake payload uses versioned format (V2+).</summary>
    VersionedPayload = 4,
    /// <summary>Frame carries a trailing HMAC-SHA256 authentication tag.</summary>
    Authenticated = 8
}

/// <summary>A wire protocol frame.</summary>
/// <param name="Type">The frame type.</param>
/// <param name="Flags">The frame flags.</param>
/// <param name="Payload">The frame payload.</param>
public sealed record Frame(FrameType Type, FrameFlags Flags, byte[] Payload);
