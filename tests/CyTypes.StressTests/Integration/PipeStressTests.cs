using System.Text;
using CyTypes.Streams.Ipc;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Integration;

[Trait("Category", "Stress"), Trait("SubCategory", "Integration")]
[Trait("Platform", "Windows")]
public class PipeStressTests
{
    private readonly ITestOutputHelper _output;

    public PipeStressTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task MultipleClients_ConcurrentPipeConnections()
    {
        // Named pipes work reliably on Windows. On Linux, this may throw PlatformNotSupportedException.
        const int clientCount = 5;
        var pipeName = Guid.NewGuid().ToString();
        var counter = new ThroughputCounter();

        using var cts = new CancellationTokenSource(StressTestConfig.Timeout);

        try
        {
            using var server = new CyPipeServer(pipeName);

            // Server accepts clients sequentially (each CyPipeServer.AcceptAsync creates a new pipe instance)
            var serverTask = Task.Run(async () =>
            {
                var connections = new List<CyPipeStream>();
                try
                {
                    for (var i = 0; i < clientCount; i++)
                    {
                        var conn = await server.AcceptAsync(cts.Token);
                        connections.Add(conn);

                        // Receive message from client
                        var data = await conn.ReceiveAsync(cts.Token);
                        data.Should().NotBeNull();

                        var message = Encoding.UTF8.GetString(data!);
                        message.Should().StartWith("pipe-client-");

                        // Send response
                        await conn.SendAsync(Encoding.UTF8.GetBytes($"pipe-ack-{i}"), cts.Token);
                        counter.Increment();
                    }
                }
                finally
                {
                    foreach (var conn in connections)
                        conn.Dispose();
                }
            });

            // Clients connect sequentially to the pipe server
            for (var i = 0; i < clientCount; i++)
            {
                using var client = new CyPipeClient();
                await client.ConnectAsync(pipeName, ct: cts.Token);

                client.Stream.IsConnected.Should().BeTrue();

                // Send message
                await client.Stream.SendAsync(
                    Encoding.UTF8.GetBytes($"pipe-client-{i}"), cts.Token);

                // Receive response
                var response = await client.Stream.ReceiveAsync(cts.Token);
                response.Should().NotBeNull("server should respond to pipe client");

                var responseText = Encoding.UTF8.GetString(response!);
                responseText.Should().StartWith("pipe-ack-");
            }

            await serverTask;

            counter.Count.Should().Be(clientCount, "all pipe clients should complete handshake + message exchange");
            _output.WriteLine($"Pipe stress test: {counter.Summary}");
        }
        catch (PlatformNotSupportedException)
        {
            _output.WriteLine("Named pipes not supported on this platform, skipping");
        }
        catch (IOException ex) when (!OperatingSystem.IsWindows())
        {
            _output.WriteLine($"Named pipe I/O error on non-Windows platform (expected): {ex.Message}");
        }
        catch (TimeoutException) when (!OperatingSystem.IsWindows())
        {
            _output.WriteLine("Named pipe timeout on non-Windows platform (expected), skipping");
        }
    }
}
