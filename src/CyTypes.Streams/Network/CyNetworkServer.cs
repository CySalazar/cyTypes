using System.Net;
using System.Net.Sockets;

namespace CyTypes.Streams.Network;

/// <summary>
/// TCP server that performs automatic hybrid key exchange on each connection.
/// </summary>
public sealed class CyNetworkServer : IDisposable
{
    private readonly TcpListener _listener;
    private bool _isDisposed;
    private bool _isStarted;

    /// <summary>
    /// Creates a new <see cref="CyNetworkServer"/> bound to the given endpoint.
    /// </summary>
    /// <param name="endpoint">The local endpoint to listen on.</param>
    public CyNetworkServer(IPEndPoint endpoint)
    {
        _listener = new TcpListener(endpoint ?? throw new ArgumentNullException(nameof(endpoint)));
    }

    /// <summary>
    /// Creates a new <see cref="CyNetworkServer"/> bound to the given address and port.
    /// </summary>
    public CyNetworkServer(IPAddress address, int port)
        : this(new IPEndPoint(address, port))
    {
    }

    /// <summary>Starts listening for connections.</summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        _listener.Start();
        _isStarted = true;
    }

    /// <summary>
    /// Accepts a client connection and performs the hybrid key exchange handshake.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A connected and handshaked <see cref="CyNetworkStream"/>.</returns>
    public async Task<CyNetworkStream> AcceptAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (!_isStarted) throw new InvalidOperationException("Server not started. Call Start() first.");

        var tcpClient = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
        var cyStream = new CyNetworkStream(tcpClient);

        await cyStream.HandshakeAsResponderAsync(ct).ConfigureAwait(false);
        return cyStream;
    }

    /// <summary>Stops listening for connections.</summary>
    public void Stop()
    {
        _listener.Stop();
        _isStarted = false;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        if (_isStarted)
            _listener.Stop();
    }
}
