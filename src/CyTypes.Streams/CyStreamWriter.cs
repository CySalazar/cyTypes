using System.Buffers.Binary;
using CyTypes.Primitives.Shared;

namespace CyTypes.Streams;

/// <summary>
/// Writes CyType values to a <see cref="CyStream"/> in a typed, framed format.
/// Each value is framed as: [typeId:2][payloadLength:4][encryptedPayload:N].
/// Values are transferred in their encrypted form — no plaintext is ever exposed.
/// </summary>
public sealed class CyStreamWriter : IDisposable
{
    private readonly CyStream _stream;
    private readonly bool _leaveOpen;
    private bool _isDisposed;

    /// <summary>
    /// Initializes a new <see cref="CyStreamWriter"/> that writes to the given <see cref="CyStream"/>.
    /// </summary>
    /// <param name="stream">The encrypted stream to write to.</param>
    /// <param name="leaveOpen">Whether to leave the stream open on disposal.</param>
    public CyStreamWriter(CyStream stream, bool leaveOpen = false)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _leaveOpen = leaveOpen;
    }

    /// <summary>
    /// Writes a CyType value to the stream in its encrypted form.
    /// </summary>
    /// <typeparam name="TSelf">The concrete CyType type.</typeparam>
    /// <typeparam name="TNative">The native value type.</typeparam>
    /// <param name="value">The CyType value to write.</param>
    public void WriteValue<TSelf, TNative>(CyTypeBase<TSelf, TNative> value)
        where TSelf : CyTypeBase<TSelf, TNative>
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(value);

        var typeId = CyTypeIds.GetTypeId<TSelf>();
        var encryptedBytes = value.GetEncryptedBytes();

        // Frame: [typeId:2][payloadLength:4][payload:N]
        Span<byte> header = stackalloc byte[6];
        BinaryPrimitives.WriteUInt16BigEndian(header[..2], typeId);
        BinaryPrimitives.WriteInt32BigEndian(header[2..6], encryptedBytes.Length);

        _stream.Write(header.ToArray(), 0, 6);
        _stream.Write(encryptedBytes, 0, encryptedBytes.Length);
    }

    /// <summary>
    /// Writes raw encrypted bytes with a type ID to the stream.
    /// </summary>
    /// <param name="typeId">The type identifier.</param>
    /// <param name="encryptedPayload">The encrypted payload bytes.</param>
    public void WriteRaw(ushort typeId, ReadOnlySpan<byte> encryptedPayload)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        Span<byte> header = stackalloc byte[6];
        BinaryPrimitives.WriteUInt16BigEndian(header[..2], typeId);
        BinaryPrimitives.WriteInt32BigEndian(header[2..6], encryptedPayload.Length);

        _stream.Write(header.ToArray(), 0, 6);
        _stream.Write(encryptedPayload.ToArray(), 0, encryptedPayload.Length);
    }

    /// <summary>Finalizes the stream writing.</summary>
    public void Complete()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        _stream.WriteFinal();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        if (!_leaveOpen)
            _stream.Dispose();
    }
}
