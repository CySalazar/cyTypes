using CyTypes.Streams.Ipc;
using Xunit;
using FluentAssertions;

namespace CyTypes.Streams.Tests;

public class CyPipeStreamTests
{
    [Fact]
    public async Task ServerClient_Handshake_And_BidirectionalExchange()
    {
        var pipeName = "CyPipeTest_" + Guid.NewGuid().ToString("N")[..8];

        using var server = new CyPipeServer(pipeName);
        using var client = new CyPipeClient();

        var serverTask = Task.Run(async () =>
        {
            await using var conn = await server.AcceptAsync();
            conn.IsConnected.Should().BeTrue();

            // Receive from client
            var data = await conn.ReceiveAsync();
            data.Should().NotBeNull();
            System.Text.Encoding.UTF8.GetString(data!).Should().Be("Hello from client");

            // Send to client
            await conn.SendAsync("Hello from server"u8.ToArray());
        });

        var clientTask = Task.Run(async () =>
        {
            await client.ConnectAsync(pipeName);
            client.Stream.IsConnected.Should().BeTrue();

            // Send to server
            await client.Stream.SendAsync("Hello from client"u8.ToArray());

            // Receive from server
            var data = await client.Stream.ReceiveAsync();
            data.Should().NotBeNull();
            System.Text.Encoding.UTF8.GetString(data!).Should().Be("Hello from server");
        });

        await Task.WhenAll(serverTask, clientTask);
    }

    [Fact]
    public async Task GracefulClose_ReturnsNull()
    {
        var pipeName = "CyPipeClose_" + Guid.NewGuid().ToString("N")[..8];

        using var server = new CyPipeServer(pipeName);
        using var client = new CyPipeClient();

        var serverTask = Task.Run(async () =>
        {
            await using var conn = await server.AcceptAsync();
            await conn.CloseAsync();
        });

        var clientTask = Task.Run(async () =>
        {
            await client.ConnectAsync(pipeName);
            var data = await client.Stream.ReceiveAsync();
            data.Should().BeNull();
        });

        await Task.WhenAll(serverTask, clientTask);
    }
}
