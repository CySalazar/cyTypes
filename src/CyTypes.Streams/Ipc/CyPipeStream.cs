using System.IO.Pipes;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.KeyExchange;
using CyTypes.Core.Memory;
using CyTypes.Streams.Protocol;

namespace CyTypes.Streams.Ipc;

/// <summary>
/// Provides bidirectional encrypted communication over a named pipe after
/// hybrid key exchange (ECDH P-256 + ML-KEM-1024).
/// Supports protocol versioning, handshake timeout, and optional HMAC-SHA256 frame authentication (V2+).
/// </summary>
public sealed class CyPipeStream : IDisposable, IAsyncDisposable
{
    private static readonly byte[] FrameHmacInfo = "CyTypes.FrameHMAC"u8.ToArray();

    private readonly PipeStream _pipeStream;
    private ChunkedCryptoEngine? _engine;
    private SecureBuffer? _sessionKey;
    private SecureBuffer? _frameHmacKey;
    private long _sendSequence;
    private long _receiveSequence;
    private int _isDisposed; // 0 = alive, 1 = disposed (atomic via Interlocked)
    private bool _isConnected;
    private byte _negotiatedVersion;
    private ProtocolCapabilities _negotiatedCapabilities;

    internal CyPipeStream(PipeStream pipeStream)
    {
        _pipeStream = pipeStream ?? throw new ArgumentNullException(nameof(pipeStream));
    }

    /// <summary>Gets whether the handshake has completed and the stream is ready for data.</summary>
    public bool IsConnected => _isConnected;

    /// <summary>Gets or sets the maximum duration allowed for the handshake phase. Defaults to 30 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Performs the handshake as the initiator (client side).
    /// </summary>
    internal async Task HandshakeAsInitiatorAsync(CancellationToken ct = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (HandshakeTimeout > TimeSpan.Zero && HandshakeTimeout != Timeout.InfiniteTimeSpan)
            timeoutCts.CancelAfter(HandshakeTimeout);
        var effectiveCt = timeoutCts.Token;

        try
        {
            using var negotiator = new SessionKeyNegotiator();

            var handshake = negotiator.CreateHandshake();
            var handshakeBytes = handshake.Serialize();
            await CyWireProtocol.WriteFrameAsync(_pipeStream, FrameType.Handshake, handshakeBytes,
                FrameFlags.VersionedPayload, effectiveCt).ConfigureAwait(false);

            var responderFrame = await CyWireProtocol.ReadFrameAsync(_pipeStream, effectiveCt).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Connection closed during handshake.");
            if (responderFrame.Type != FrameType.Handshake)
                throw new InvalidOperationException($"Expected Handshake frame, got {responderFrame.Type}.");

            var responderHandshake = HandshakeMessage.Deserialize(responderFrame.Payload);
            NegotiateProtocol(handshake, responderHandshake);

            var (sessionKey, mlKemCiphertext) = negotiator.DeriveSessionKeyAsInitiator(responderHandshake);
            _sessionKey = sessionKey;

            await CyWireProtocol.WriteFrameAsync(_pipeStream, FrameType.Handshake, mlKemCiphertext,
                FrameFlags.HandshakeResponse, effectiveCt).ConfigureAwait(false);

            _engine = new ChunkedCryptoEngine(_sessionKey.AsReadOnlySpan(), 65536);
            DeriveFrameHmacKey();
            _isConnected = true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"Handshake did not complete within {HandshakeTimeout.TotalSeconds:F0} seconds.");
        }
    }

    /// <summary>
    /// Performs the handshake as the responder (server side).
    /// </summary>
    internal async Task HandshakeAsResponderAsync(CancellationToken ct = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (HandshakeTimeout > TimeSpan.Zero && HandshakeTimeout != Timeout.InfiniteTimeSpan)
            timeoutCts.CancelAfter(HandshakeTimeout);
        var effectiveCt = timeoutCts.Token;

        try
        {
            using var negotiator = new SessionKeyNegotiator();

            var initiatorFrame = await CyWireProtocol.ReadFrameAsync(_pipeStream, effectiveCt).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Connection closed during handshake.");
            if (initiatorFrame.Type != FrameType.Handshake)
                throw new InvalidOperationException($"Expected Handshake frame, got {initiatorFrame.Type}.");

            var initiatorHandshake = HandshakeMessage.Deserialize(initiatorFrame.Payload);

            var handshake = negotiator.CreateHandshake();
            var handshakeBytes = handshake.Serialize();
            await CyWireProtocol.WriteFrameAsync(_pipeStream, FrameType.Handshake, handshakeBytes,
                FrameFlags.VersionedPayload, effectiveCt).ConfigureAwait(false);

            NegotiateProtocol(handshake, initiatorHandshake);

            var mlKemFrame = await CyWireProtocol.ReadFrameAsync(_pipeStream, effectiveCt).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Connection closed during handshake.");
            if (mlKemFrame.Type != FrameType.Handshake || (mlKemFrame.Flags & FrameFlags.HandshakeResponse) == 0)
                throw new InvalidOperationException("Expected ML-KEM handshake response.");

            _sessionKey = negotiator.DeriveSessionKeyAsResponder(initiatorHandshake, mlKemFrame.Payload);
            _engine = new ChunkedCryptoEngine(_sessionKey.AsReadOnlySpan(), 65536);
            DeriveFrameHmacKey();
            _isConnected = true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"Handshake did not complete within {HandshakeTimeout.TotalSeconds:F0} seconds.");
        }
    }

    private void NegotiateProtocol(HandshakeMessage ours, HandshakeMessage peer)
    {
        _negotiatedVersion = Math.Min(ours.Version, peer.Version);
        _negotiatedCapabilities = ours.Capabilities & peer.Capabilities;
    }

    private void DeriveFrameHmacKey()
    {
        if ((_negotiatedCapabilities & ProtocolCapabilities.FrameHmac) == 0 || _sessionKey == null)
            return;

        var hmacKeyBytes = HkdfKeyDerivation.DeriveKey(
            _sessionKey.AsReadOnlySpan(), outputLength: 32, info: FrameHmacInfo);
        _frameHmacKey = new SecureBuffer(32);
        _frameHmacKey.Write(hmacKeyBytes);
        CryptographicOperations.ZeroMemory(hmacKeyBytes);
    }

    private bool UseFrameHmac => _frameHmacKey != null;

    /// <summary>Sends encrypted data to the peer.</summary>
    public async Task SendAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        if (!_isConnected) throw new InvalidOperationException("Handshake not completed.");

        var encrypted = _engine!.EncryptChunk(data.Span, _sendSequence++, false);
        if (UseFrameHmac)
            await CyWireProtocol.WriteAuthenticatedFrameAsync(_pipeStream, FrameType.Data, encrypted,
                _frameHmacKey!.AsReadOnlySpan(), ct: ct).ConfigureAwait(false);
        else
            await CyWireProtocol.WriteFrameAsync(_pipeStream, FrameType.Data, encrypted, ct: ct)
                .ConfigureAwait(false);
    }

    /// <summary>Receives and decrypts data from the peer.</summary>
    /// <returns>The decrypted data, or <c>null</c> if the connection was closed.</returns>
    public async Task<byte[]?> ReceiveAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        if (!_isConnected) throw new InvalidOperationException("Handshake not completed.");

        var frame = UseFrameHmac
            ? await CyWireProtocol.ReadAuthenticatedFrameAsync(_pipeStream, _frameHmacKey!.AsReadOnlySpan(), ct).ConfigureAwait(false)
            : await CyWireProtocol.ReadFrameAsync(_pipeStream, ct).ConfigureAwait(false);
        if (frame == null) return null;

        return frame.Type switch
        {
            FrameType.Data => _engine!.DecryptChunk(frame.Payload, _receiveSequence++, out _),
            FrameType.Close => null,
            FrameType.Heartbeat => await ReceiveAsync(ct).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Unexpected frame type: {frame.Type}.")
        };
    }

    /// <summary>Sends a graceful close frame.</summary>
    public async Task CloseAsync(CancellationToken ct = default)
    {
        if (Volatile.Read(ref _isDisposed) == 1 || !_isConnected) return;
        if (UseFrameHmac)
            await CyWireProtocol.WriteAuthenticatedFrameAsync(_pipeStream, FrameType.Close,
                ReadOnlyMemory<byte>.Empty, _frameHmacKey!.AsReadOnlySpan(), ct: ct).ConfigureAwait(false);
        else
            await CyWireProtocol.WriteFrameAsync(_pipeStream, FrameType.Close,
                ReadOnlyMemory<byte>.Empty, ct: ct).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        _engine?.Dispose();
        _frameHmacKey?.Dispose();
        _sessionKey?.Dispose();
        _pipeStream.Dispose();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        _engine?.Dispose();
        _frameHmacKey?.Dispose();
        _sessionKey?.Dispose();
        await _pipeStream.DisposeAsync().ConfigureAwait(false);
    }
}
