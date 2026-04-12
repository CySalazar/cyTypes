using System.Net.Sockets;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.KeyExchange;
using CyTypes.Core.Memory;
using CyTypes.Streams.Protocol;

namespace CyTypes.Streams.Network;

/// <summary>
/// Provides bidirectional encrypted communication over TCP after
/// hybrid key exchange (ECDH P-256 + ML-KEM-1024).
/// Supports heartbeat, configurable timeouts, protocol versioning,
/// and optional HMAC-SHA256 frame authentication (V2+).
/// </summary>
public sealed class CyNetworkStream : IDisposable, IAsyncDisposable
{
    private static readonly byte[] FrameHmacInfo = "CyTypes.FrameHMAC"u8.ToArray();

    private readonly NetworkStream _networkStream;
    private readonly TcpClient _tcpClient;
    private ChunkedCryptoEngine? _engine;
    private SecureBuffer? _sessionKey;
    private SecureBuffer? _frameHmacKey;
    private long _sendSequence;
    private long _receiveSequence;
    private int _isDisposed; // 0 = alive, 1 = disposed (atomic via Interlocked)
    private bool _isConnected;
    private Timer? _heartbeatTimer;
    private byte _negotiatedVersion;
    private ProtocolCapabilities _negotiatedCapabilities;

    /// <summary>Gets or sets the heartbeat interval. Set to <see cref="TimeSpan.Zero"/> to disable.</summary>
    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets or sets the receive timeout.</summary>
    public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Gets or sets the maximum duration allowed for the handshake phase. Defaults to 30 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets whether the handshake has completed.</summary>
    public bool IsConnected => _isConnected;

    /// <summary>Gets the negotiated protocol version after handshake.</summary>
    public byte NegotiatedVersion => _negotiatedVersion;

    /// <summary>Gets the negotiated capabilities after handshake.</summary>
    public ProtocolCapabilities NegotiatedCapabilities => _negotiatedCapabilities;

    internal CyNetworkStream(TcpClient tcpClient)
    {
        _tcpClient = tcpClient ?? throw new ArgumentNullException(nameof(tcpClient));
        _networkStream = tcpClient.GetStream();
    }

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

            // Send our V2 handshake with VersionedPayload flag
            var handshake = negotiator.CreateHandshake();
            var handshakeBytes = handshake.Serialize();
            await CyWireProtocol.WriteFrameAsync(_networkStream, FrameType.Handshake, handshakeBytes,
                FrameFlags.VersionedPayload, effectiveCt).ConfigureAwait(false);

            // Receive responder handshake
            var responderFrame = await CyWireProtocol.ReadFrameAsync(_networkStream, effectiveCt).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Connection closed during handshake.");
            if (responderFrame.Type != FrameType.Handshake)
                throw new InvalidOperationException($"Expected Handshake frame, got {responderFrame.Type}.");

            var responderHandshake = HandshakeMessage.Deserialize(responderFrame.Payload);

            // Negotiate version and capabilities
            NegotiateProtocol(handshake, responderHandshake);

            // Derive session key and encapsulate ML-KEM
            var (sessionKey, mlKemCiphertext) = negotiator.DeriveSessionKeyAsInitiator(responderHandshake);
            _sessionKey = sessionKey;

            // Send ML-KEM ciphertext
            await CyWireProtocol.WriteFrameAsync(_networkStream, FrameType.Handshake, mlKemCiphertext,
                FrameFlags.HandshakeResponse, effectiveCt).ConfigureAwait(false);

            _engine = new ChunkedCryptoEngine(_sessionKey.AsReadOnlySpan(), 65536);
            DeriveFrameHmacKey();
            _isConnected = true;
            StartHeartbeat();
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

            // Receive initiator handshake
            var initiatorFrame = await CyWireProtocol.ReadFrameAsync(_networkStream, effectiveCt).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Connection closed during handshake.");
            if (initiatorFrame.Type != FrameType.Handshake)
                throw new InvalidOperationException($"Expected Handshake frame, got {initiatorFrame.Type}.");

            var initiatorHandshake = HandshakeMessage.Deserialize(initiatorFrame.Payload);

            // Send our V2 handshake with VersionedPayload flag
            var handshake = negotiator.CreateHandshake();
            var handshakeBytes = handshake.Serialize();
            await CyWireProtocol.WriteFrameAsync(_networkStream, FrameType.Handshake, handshakeBytes,
                FrameFlags.VersionedPayload, effectiveCt).ConfigureAwait(false);

            // Negotiate version and capabilities
            NegotiateProtocol(handshake, initiatorHandshake);

            // Receive ML-KEM ciphertext
            var mlKemFrame = await CyWireProtocol.ReadFrameAsync(_networkStream, effectiveCt).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Connection closed during handshake.");
            if (mlKemFrame.Type != FrameType.Handshake || (mlKemFrame.Flags & FrameFlags.HandshakeResponse) == 0)
                throw new InvalidOperationException("Expected ML-KEM handshake response.");

            _sessionKey = negotiator.DeriveSessionKeyAsResponder(initiatorHandshake, mlKemFrame.Payload);
            _engine = new ChunkedCryptoEngine(_sessionKey.AsReadOnlySpan(), 65536);
            DeriveFrameHmacKey();
            _isConnected = true;
            StartHeartbeat();
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
            await CyWireProtocol.WriteAuthenticatedFrameAsync(_networkStream, FrameType.Data, encrypted,
                _frameHmacKey!.AsReadOnlySpan(), ct: ct).ConfigureAwait(false);
        else
            await CyWireProtocol.WriteFrameAsync(_networkStream, FrameType.Data, encrypted, ct: ct)
                .ConfigureAwait(false);
    }

    /// <summary>Receives and decrypts data from the peer.</summary>
    /// <returns>The decrypted data, or <c>null</c> if the connection was closed.</returns>
    public async Task<byte[]?> ReceiveAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        if (!_isConnected) throw new InvalidOperationException("Handshake not completed.");

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (ReceiveTimeout > TimeSpan.Zero)
            timeoutCts.CancelAfter(ReceiveTimeout);

        var frame = UseFrameHmac
            ? await CyWireProtocol.ReadAuthenticatedFrameAsync(_networkStream, _frameHmacKey!.AsReadOnlySpan(), timeoutCts.Token).ConfigureAwait(false)
            : await CyWireProtocol.ReadFrameAsync(_networkStream, timeoutCts.Token).ConfigureAwait(false);
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

        try
        {
            if (UseFrameHmac)
                await CyWireProtocol.WriteAuthenticatedFrameAsync(_networkStream, FrameType.Close,
                    ReadOnlyMemory<byte>.Empty, _frameHmacKey!.AsReadOnlySpan(), ct: ct).ConfigureAwait(false);
            else
                await CyWireProtocol.WriteFrameAsync(_networkStream, FrameType.Close,
                    ReadOnlyMemory<byte>.Empty, ct: ct).ConfigureAwait(false);
        }
        catch (IOException) { /* Connection may already be closed */ }
        catch (ObjectDisposedException) { }
    }

    private void StartHeartbeat()
    {
        if (HeartbeatInterval <= TimeSpan.Zero) return;

        _heartbeatTimer = new Timer(async _ =>
        {
            if (Volatile.Read(ref _isDisposed) == 1 || !_isConnected) return;
            try
            {
                if (UseFrameHmac)
                    await CyWireProtocol.WriteAuthenticatedFrameAsync(_networkStream, FrameType.Heartbeat,
                        ReadOnlyMemory<byte>.Empty, _frameHmacKey!.AsReadOnlySpan()).ConfigureAwait(false);
                else
                    await CyWireProtocol.WriteFrameAsync(_networkStream, FrameType.Heartbeat,
                        ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            }
            catch { /* Ignore heartbeat failures */ }
        }, null, HeartbeatInterval, HeartbeatInterval);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        _heartbeatTimer?.Dispose();
        _engine?.Dispose();
        _frameHmacKey?.Dispose();
        _sessionKey?.Dispose();
        _networkStream.Dispose();
        _tcpClient.Dispose();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        if (_heartbeatTimer != null)
            await _heartbeatTimer.DisposeAsync().ConfigureAwait(false);
        _engine?.Dispose();
        _frameHmacKey?.Dispose();
        _sessionKey?.Dispose();
        await _networkStream.DisposeAsync().ConfigureAwait(false);
        _tcpClient.Dispose();
    }
}
