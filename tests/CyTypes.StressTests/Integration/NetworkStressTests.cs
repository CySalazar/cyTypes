using System.Collections.Concurrent;
using System.Net;
using System.Text;
using CyTypes.Streams.Network;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Integration;

[Trait("Category", "Stress"), Trait("SubCategory", "Integration")]
public class NetworkStressTests
{
    private readonly ITestOutputHelper _output;

    public NetworkStressTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task MultipleClients_ConcurrentHandshake()
    {
        // Arrange: 10 clients connect concurrently to a server
        const int clientCount = 10;
        var port = PortAllocator.GetFreePort();
        using var server = new CyNetworkServer(IPAddress.Loopback, port);
        server.Start();

        var exceptions = new ConcurrentBag<Exception>();
        var successfulHandshakes = 0;

        using var cts = new CancellationTokenSource(StressTestConfig.Timeout);

        // Act: Server accepts connections
        var serverTask = Task.Run(async () =>
        {
            var connections = new List<CyNetworkStream>();
            try
            {
                for (var i = 0; i < clientCount; i++)
                {
                    var conn = await server.AcceptAsync(cts.Token);
                    connections.Add(conn);

                    // Receive a message from each client
                    var data = await conn.ReceiveAsync(cts.Token);
                    data.Should().NotBeNull();

                    // Send a response
                    await conn.SendAsync(Encoding.UTF8.GetBytes($"ack-{i}"), cts.Token);
                }
            }
            catch (Exception ex) when (!cts.IsCancellationRequested)
            {
                exceptions.Add(ex);
            }
            finally
            {
                foreach (var conn in connections)
                    conn.Dispose();
            }
        });

        // Act: Clients connect concurrently
        var clientTasks = Enumerable.Range(0, clientCount).Select(clientId => Task.Run(async () =>
        {
            try
            {
                using var client = new CyNetworkClient();
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), cts.Token);

                client.Stream.IsConnected.Should().BeTrue();

                // Send a message
                var message = Encoding.UTF8.GetBytes($"hello-from-{clientId}");
                await client.Stream.SendAsync(message, cts.Token);

                // Receive response
                var response = await client.Stream.ReceiveAsync(cts.Token);
                response.Should().NotBeNull("server should respond");

                Interlocked.Increment(ref successfulHandshakes);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        })).ToArray();

        await Task.WhenAll(clientTasks);
        await serverTask;

        // Assert
        exceptions.Should().BeEmpty("all handshakes and message exchanges should succeed");
        successfulHandshakes.Should().Be(clientCount, "all clients should complete handshake");

        _output.WriteLine($"Successfully connected {clientCount} clients with concurrent handshakes");
    }

    [Fact]
    public async Task Client_Disconnect_ServerRecovers()
    {
        // Arrange
        var port = PortAllocator.GetFreePort();
        using var server = new CyNetworkServer(IPAddress.Loopback, port);
        server.Start();

        using var cts = new CancellationTokenSource(StressTestConfig.Timeout);

        // Act: First client connects, sends data, disconnects
        var serverAccept1 = Task.Run(async () =>
        {
            var conn = await server.AcceptAsync(cts.Token);
            var data = await conn.ReceiveAsync(cts.Token);
            data.Should().NotBeNull();
            conn.Dispose(); // Server disposes the connection
            return true;
        });

        using (var client1 = new CyNetworkClient())
        {
            await client1.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), cts.Token);
            await client1.Stream.SendAsync(Encoding.UTF8.GetBytes("first-client"), cts.Token);
        }

        var firstCompleted = await serverAccept1;
        firstCompleted.Should().BeTrue("first client interaction should succeed");

        // Act: Second client connects after first disconnects
        var serverAccept2 = Task.Run(async () =>
        {
            var conn = await server.AcceptAsync(cts.Token);
            var data = await conn.ReceiveAsync(cts.Token);
            data.Should().NotBeNull();

            // Send response to verify full bidirectional communication
            await conn.SendAsync(Encoding.UTF8.GetBytes("server-alive"), cts.Token);
            conn.Dispose();
            return true;
        });

        using (var client2 = new CyNetworkClient())
        {
            await client2.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), cts.Token);
            await client2.Stream.SendAsync(Encoding.UTF8.GetBytes("second-client"), cts.Token);
            var response = await client2.Stream.ReceiveAsync(cts.Token);
            response.Should().NotBeNull("server should respond to second client");

            var responseText = Encoding.UTF8.GetString(response!);
            responseText.Should().Be("server-alive");
        }

        var secondCompleted = await serverAccept2;
        secondCompleted.Should().BeTrue("server should recover and accept new clients after disconnect");

        _output.WriteLine("Server successfully recovered after client disconnect");
    }
}
