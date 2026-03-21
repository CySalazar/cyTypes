using CyTypes.Core.Crypto;

namespace CyTypes.Streams.File;

/// <summary>
/// Configuration options for <see cref="CyFileStream"/>.
/// </summary>
public sealed class SecureFileOptions
{
    /// <summary>Gets or sets the plaintext chunk size in bytes. Default is 65536 (64 KB).</summary>
    public int ChunkSize { get; set; } = 65536;

    /// <summary>
    /// Gets or sets an optional passphrase from which the encryption key will be derived via HKDF.
    /// If null, a key must be provided directly.
    /// </summary>
    public string? Passphrase { get; set; }

    /// <summary>Gets or sets the stream flags.</summary>
    public StreamSerializationFormat.StreamOption Flags { get; set; } = StreamSerializationFormat.StreamOption.None;

    /// <summary>Gets or sets whether to use atomic writes (write to temp file, then rename). Default is true.</summary>
    public bool AtomicWrite { get; set; } = true;
}
