using System.Net;
using System.Net.Sockets;

namespace CyTypes.StressTests.Infrastructure;

/// <summary>
/// Thread-safe TCP port allocator for network stress tests.
/// </summary>
public static class PortAllocator
{
    public static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
