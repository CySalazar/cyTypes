using System.Net;
using System.Net.Sockets;

namespace CyTypes.AI.Attachments;

/// <summary>
/// Restricts download URLs to a fixed allow-list of public model-hosting hosts
/// and rejects any URL that resolves to a loopback / link-local / private IP
/// range. Used by <see cref="Extractors.TessdataDownloader"/> and
/// <see cref="Extractors.WhisperModelDownloader"/> to defend against SSRF when
/// the base URL is overridden via env var.
/// </summary>
public static class SafeUrlValidator
{
    public static readonly IReadOnlySet<string> AllowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "huggingface.co",
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",  // GitHub LFS / release assets
        "cdn-lfs.huggingface.co",
        "cdn-lfs.hf.co",
    };

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> if <paramref name="url"/>
    /// is not safe to fetch (non-https, non-allowed host, or resolves to a
    /// private/loopback/link-local IP). The validation runs only the host
    /// component — paths and query strings are not inspected.
    /// </summary>
    public static void EnsureSafe(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"URL '{url}' is not a valid absolute URI");
        if (uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException($"URL '{url}' must use https");
        if (!AllowedHosts.Contains(uri.Host))
            throw new InvalidOperationException(
                $"URL host '{uri.Host}' is not in the allow-list. " +
                $"Allowed: {string.Join(", ", AllowedHosts)}");

        // Resolve and reject private / loopback / link-local addresses to
        // defend against DNS rebinding and the case where an attacker controls
        // an allow-listed name's DNS but resolves it to an internal IP.
        IPAddress[] addresses;
        try { addresses = Dns.GetHostAddresses(uri.Host); }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Could not resolve '{uri.Host}': {ex.Message}");
        }
        foreach (var addr in addresses)
        {
            if (IsPrivate(addr))
                throw new InvalidOperationException(
                    $"URL host '{uri.Host}' resolves to a private/loopback IP ({addr}); refusing");
        }
    }

    private static bool IsPrivate(IPAddress addr)
    {
        if (IPAddress.IsLoopback(addr)) return true;
        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // Reject IPv4-mapped private ranges via the projection back to v4
            if (addr.IsIPv4MappedToIPv6) return IsPrivate(addr.MapToIPv4());
            if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || addr.IsIPv6UniqueLocal) return true;
            return false;
        }
        if (addr.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = addr.GetAddressBytes();
        // 10.0.0.0/8
        if (b[0] == 10) return true;
        // 172.16.0.0/12
        if (b[0] == 172 && (b[1] & 0xF0) == 16) return true;
        // 192.168.0.0/16
        if (b[0] == 192 && b[1] == 168) return true;
        // 169.254.0.0/16  link-local + AWS IMDS / Azure IMDS
        if (b[0] == 169 && b[1] == 254) return true;
        // 100.64.0.0/10 carrier-grade NAT
        if (b[0] == 100 && (b[1] & 0xC0) == 64) return true;
        // 0.0.0.0/8
        if (b[0] == 0) return true;
        return false;
    }
}
