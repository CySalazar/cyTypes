using System.Buffers.Binary;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace CyTypes.Core.Crypto;

/// <summary>
/// Binary format for CyStream files and protocols.
/// Header: [magic:"CySt" 4B][version:1][keyId:16][chunkSize:4][flags:1][reserved:6] = 32 bytes.
/// Footer: [totalChunks:8][HMAC-SHA512:64] = 72 bytes.
/// The HMAC covers the header and all GCM tags from each chunk.
/// </summary>
public static class StreamSerializationFormat
{
    /// <summary>Magic bytes identifying a CyStream.</summary>
    public static ReadOnlySpan<byte> Magic => "CySt"u8;

    /// <summary>Current format version.</summary>
    public const byte CurrentVersion = 1;

    /// <summary>Total header size in bytes.</summary>
    public const int HeaderSize = 32;

    /// <summary>Total footer size in bytes.</summary>
    public const int FooterSize = 72;

    /// <summary>HMAC-SHA512 length in bytes.</summary>
    public const int HmacLength = 64;

    private const int MagicOffset = 0;
    private const int MagicLength = 4;
    private const int VersionOffset = 4;
    private const int KeyIdOffset = 5;
    private const int KeyIdLength = 16;
    private const int ChunkSizeOffset = 21;
    private const int FlagsOffset = 25;
    private const int ReservedOffset = 26;
    private const int ReservedLength = 6;

    private static readonly byte[] HmacInfo = Encoding.UTF8.GetBytes("CyTypes.StreamSerialization.HMAC");

    /// <summary>Stream flags.</summary>
    [Flags]
    public enum StreamOption : byte
    {
        /// <summary>No flags set.</summary>
        None = 0,
        /// <summary>The stream key was derived from a passphrase.</summary>
        PassphraseDerived = 1,
        /// <summary>The stream uses key exchange for session key negotiation.</summary>
        KeyExchange = 2
    }

    /// <summary>Writes a stream header to the given buffer.</summary>
    /// <param name="buffer">A buffer of at least <see cref="HeaderSize"/> bytes.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="chunkSize">The plaintext chunk size.</param>
    /// <param name="flags">Optional stream flags.</param>
    public static void WriteHeader(Span<byte> buffer, Guid keyId, int chunkSize, StreamOption flags = StreamOption.None)
    {
        if (buffer.Length < HeaderSize)
            throw new ArgumentException($"Buffer must be at least {HeaderSize} bytes.", nameof(buffer));

        buffer.Clear();
        Magic.CopyTo(buffer[MagicOffset..]);
        buffer[VersionOffset] = CurrentVersion;
        keyId.TryWriteBytes(buffer.Slice(KeyIdOffset, KeyIdLength));
        BinaryPrimitives.WriteInt32BigEndian(buffer.Slice(ChunkSizeOffset, 4), chunkSize);
        buffer[FlagsOffset] = (byte)flags;
        // Reserved bytes are already zeroed
    }

    /// <summary>Reads and validates a stream header.</summary>
    /// <param name="header">The header bytes to parse.</param>
    /// <returns>The parsed key ID, chunk size, and flags.</returns>
    public static (Guid KeyId, int ChunkSize, StreamOption Flags) ReadHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderSize)
            throw new ArgumentException($"Header must be at least {HeaderSize} bytes.", nameof(header));

        if (!header[MagicOffset..(MagicOffset + MagicLength)].SequenceEqual(Magic))
            throw new SecurityException("Invalid stream magic bytes. Not a CyStream.");

        if (header[VersionOffset] != CurrentVersion)
            throw new ArgumentException(
                $"Unsupported stream version {header[VersionOffset]}. Expected {CurrentVersion}.");

        var keyId = new Guid(header.Slice(KeyIdOffset, KeyIdLength));
        var chunkSize = BinaryPrimitives.ReadInt32BigEndian(header.Slice(ChunkSizeOffset, 4));
        var flags = (StreamOption)header[FlagsOffset];

        return (keyId, chunkSize, flags);
    }

    /// <summary>Writes the stream footer containing the total chunk count and HMAC.</summary>
    /// <param name="buffer">A buffer of at least <see cref="FooterSize"/> bytes.</param>
    /// <param name="totalChunks">The total number of chunks written.</param>
    /// <param name="hmacKey">The HMAC key (derived from the stream key).</param>
    /// <param name="authenticatedData">The data to authenticate (header + concatenated GCM tags).</param>
    public static void WriteFooter(
        Span<byte> buffer,
        long totalChunks,
        ReadOnlySpan<byte> hmacKey,
        ReadOnlySpan<byte> authenticatedData)
    {
        if (buffer.Length < FooterSize)
            throw new ArgumentException($"Buffer must be at least {FooterSize} bytes.", nameof(buffer));

        BinaryPrimitives.WriteInt64BigEndian(buffer[..8], totalChunks);

        var hmac = HmacComparer.Compute(hmacKey, authenticatedData);
        hmac.AsSpan().CopyTo(buffer.Slice(8, HmacLength));
    }

    /// <summary>Reads and verifies the stream footer.</summary>
    /// <param name="footer">The footer bytes.</param>
    /// <param name="hmacKey">The HMAC key.</param>
    /// <param name="authenticatedData">The data that was authenticated.</param>
    /// <returns>The total number of chunks.</returns>
    public static long ReadFooter(
        ReadOnlySpan<byte> footer,
        ReadOnlySpan<byte> hmacKey,
        ReadOnlySpan<byte> authenticatedData)
    {
        if (footer.Length < FooterSize)
            throw new ArgumentException($"Footer must be at least {FooterSize} bytes.", nameof(footer));

        var totalChunks = BinaryPrimitives.ReadInt64BigEndian(footer[..8]);
        var providedHmac = footer.Slice(8, HmacLength);

        if (!HmacComparer.Verify(hmacKey, authenticatedData, providedHmac))
            throw new SecurityException("Stream HMAC verification failed. The stream has been tampered with.");

        return totalChunks;
    }

    /// <summary>Derives an HMAC subkey from a stream encryption key.</summary>
    /// <param name="streamKey">The stream encryption key.</param>
    /// <returns>The 64-byte HMAC subkey. Caller must zero this after use.</returns>
    public static byte[] DeriveHmacKey(ReadOnlySpan<byte> streamKey)
    {
        return HkdfKeyDerivation.DeriveKey(streamKey, outputLength: 64, info: HmacInfo);
    }
}
