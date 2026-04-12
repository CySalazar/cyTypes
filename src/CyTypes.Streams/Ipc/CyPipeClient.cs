using System.IO.Pipes;

namespace CyTypes.Streams.Ipc;

/// <summary>
/// Named pipe client that connects to a <see cref="CyPipeServer"/> and performs
/// automatic hybrid key exchange.
/// </summary>
public sealed class CyPipeClient : IDisposable
{
    private CyPipeStream? _pipeStream;
    private bool _isDisposed;

    /// <summary>Gets or sets the maximum duration allowed for the handshake phase. Defaults to 30 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets the underlying <see cref="CyPipeStream"/> after connection.</summary>
    public CyPipeStream Stream => _pipeStream ?? throw new InvalidOperationException("Not connected.");

    /// <summary>
    /// Connects to the named pipe server and performs the hybrid key exchange handshake.
    /// </summary>
    /// <param name="pipeName">The named pipe name.</param>
    /// <param name="serverName">The server name. Default is "." (local machine).</param>
    /// <param name="timeout">Connection timeout in milliseconds. Default is 5000.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task ConnectAsync(
        string pipeName,
        string serverName = ".",
        int timeout = 5000,
        CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        var clientPipe = new NamedPipeClientStream(
            serverName,
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        await clientPipe.ConnectAsync(timeout, ct).ConfigureAwait(false);

        _pipeStream = new CyPipeStream(clientPipe);
        _pipeStream.HandshakeTimeout = HandshakeTimeout;
        await _pipeStream.HandshakeAsInitiatorAsync(ct).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        _pipeStream?.Dispose();
    }
}
