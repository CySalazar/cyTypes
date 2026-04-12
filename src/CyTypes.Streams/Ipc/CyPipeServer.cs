using System.IO.Pipes;

namespace CyTypes.Streams.Ipc;

/// <summary>
/// Named pipe server that performs automatic hybrid key exchange on each connection.
/// </summary>
public sealed class CyPipeServer : IDisposable
{
    private readonly string _pipeName;
    private bool _isDisposed;

    /// <summary>Gets or sets the maximum duration allowed for the handshake phase. Defaults to 30 seconds.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Creates a new <see cref="CyPipeServer"/> listening on the given pipe name.
    /// </summary>
    /// <param name="pipeName">The named pipe name.</param>
    public CyPipeServer(string pipeName)
    {
        _pipeName = pipeName ?? throw new ArgumentNullException(nameof(pipeName));
    }

    /// <summary>
    /// Waits for a client connection and performs the hybrid key exchange handshake.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A connected and handshaked <see cref="CyPipeStream"/>.</returns>
    public async Task<CyPipeStream> AcceptAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        var serverPipe = new NamedPipeServerStream(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);

        await serverPipe.WaitForConnectionAsync(ct).ConfigureAwait(false);

        var cyPipe = new CyPipeStream(serverPipe);
        cyPipe.HandshakeTimeout = HandshakeTimeout;
        await cyPipe.HandshakeAsResponderAsync(ct).ConfigureAwait(false);

        return cyPipe;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _isDisposed = true;
    }
}
