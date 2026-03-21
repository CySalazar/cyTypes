using System.Net;
using CyTypes.Streams.Network;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class CyNetworkStreamTests
{
    [Fact]
    public async Task ServerClient_Handshake_And_BidirectionalExchange()
    {
        var port = GetFreePort();

        using var server = new CyNetworkServer(IPAddress.Loopback, port);
        server.Start();

        using var client = new CyNetworkClient();

        var serverTask = Task.Run(async () =>
        {
            await using var conn = await server.AcceptAsync();
            conn.IsConnected.Should().BeTrue();

            // Receive from client
            var data = await conn.ReceiveAsync();
            data.Should().NotBeNull();
            System.Text.Encoding.UTF8.GetString(data!).Should().Be("Hello TCP");

            // Send to client
            await conn.SendAsync("Reply TCP"u8.ToArray());
        });

        var clientTask = Task.Run(async () =>
        {
            await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
            client.Stream.IsConnected.Should().BeTrue();

            // Send to server
            await client.Stream.SendAsync("Hello TCP"u8.ToArray());

            // Receive from server
            var data = await client.Stream.ReceiveAsync();
            data.Should().NotBeNull();
            System.Text.Encoding.UTF8.GetString(data!).Should().Be("Reply TCP");
        });

        await Task.WhenAll(serverTask, clientTask);
    }

    [Fact]
    public async Task GracefulClose_ReturnsNull()
    {
        var port = GetFreePort();

        using var server = new CyNetworkServer(IPAddress.Loopback, port);
        server.Start();

        using var client = new CyNetworkClient();

        var serverTask = Task.Run(async () =>
        {
            await using var conn = await server.AcceptAsync();
            await conn.CloseAsync();
        });

        var clientTask = Task.Run(async () =>
        {
            await client.ConnectAsync("127.0.0.1", port);
            var data = await client.Stream.ReceiveAsync();
            data.Should().BeNull();
        });

        await Task.WhenAll(serverTask, clientTask);
    }

    private static int GetFreePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
