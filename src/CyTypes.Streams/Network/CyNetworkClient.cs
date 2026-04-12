using System.Net;
using System.Net.Sockets;

namespace CyTypes.Streams.Network;

/// <summary>
/// TCP client that connects to a <see cref="CyNetworkServer"/> and performs
/// automatic hybrid key exchange.
/// </summary>
public sealed class CyNetworkClient : IDisposable, IAsyncDisposable
{
    private CyNetworkStream? _networkStream;
    private bool _isDisposed;

    /// <summary>Gets or sets the maximum duration allowed for the handshake phase. Defaults to 30 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets the underlying <see cref="CyNetworkStream"/> after connection.</summary>
    public CyNetworkStream Stream => _networkStream ?? throw new InvalidOperationException("Not connected.");

    /// <summary>
    /// Connects to the server and performs the hybrid key exchange handshake.
    /// </summary>
    /// <param name="endpoint">The remote endpoint to connect to.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task ConnectAsync(IPEndPoint endpoint, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(endpoint, ct).ConfigureAwait(false);

        _networkStream = new CyNetworkStream(tcpClient);
        _networkStream.HandshakeTimeout = HandshakeTimeout;
        await _networkStream.HandshakeAsInitiatorAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Connects to the server and performs the hybrid key exchange handshake.
    /// </summary>
    /// <param name="host">The host name or IP address.</param>
    /// <param name="port">The port number.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task ConnectAsync(string host, int port, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(host, port, ct).ConfigureAwait(false);

        _networkStream = new CyNetworkStream(tcpClient);
        _networkStream.HandshakeTimeout = HandshakeTimeout;
        await _networkStream.HandshakeAsInitiatorAsync(ct).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        _networkStream?.Dispose();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        if (_networkStream != null)
            await _networkStream.DisposeAsync().ConfigureAwait(false);
    }
}
