using System.Security.Cryptography;
using System.Text;
using CyTypes.Core.Crypto;
using CyTypes.Core.Memory;

namespace CyTypes.Streams.File;

/// <summary>
/// Provides encrypted file I/O by wrapping a <see cref="FileStream"/> in a <see cref="CyStream"/>.
/// Supports atomic writes (write to temp file, rename on close) and passphrase-derived keys.
/// </summary>
public sealed class CyFileStream : IDisposable, IAsyncDisposable
{
    private static readonly byte[] PassphraseInfo = Encoding.UTF8.GetBytes("CyTypes.FileStream.Passphrase");

    private readonly CyStream _cyStream;
    private readonly string? _tempPath;
    private readonly string? _finalPath;
    private readonly SecureBuffer? _derivedKey;
    private int _isDisposed; // 0 = alive, 1 = disposed (atomic via Interlocked)

    private CyFileStream(CyStream cyStream, string? tempPath, string? finalPath, SecureBuffer? derivedKey)
    {
        _cyStream = cyStream;
        _tempPath = tempPath;
        _finalPath = finalPath;
        _derivedKey = derivedKey;
    }

    /// <summary>Opens an encrypted file for reading.</summary>
    /// <param name="path">The file path.</param>
    /// <param name="key">The 256-bit encryption key.</param>
    public static CyFileStream OpenRead(string path, ReadOnlySpan<byte> key)
    {
        var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var cyStream = CyStream.CreateReader(fileStream, key);
        return new CyFileStream(cyStream, null, null, null);
    }

    /// <summary>Opens an encrypted file for reading with a passphrase-derived key.</summary>
    /// <param name="path">The file path.</param>
    /// <param name="passphrase">The passphrase.</param>
    public static CyFileStream OpenRead(string path, string passphrase)
    {
        // Read the header first to get the salt (stored in the reserved bytes area)
        using var peekStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var headerBytes = new byte[StreamSerializationFormat.HeaderSize];
        peekStream.ReadExactly(headerBytes);
        peekStream.Close();

        // Use keyId as the salt for passphrase derivation
        var (keyId, _, _) = StreamSerializationFormat.ReadHeader(headerBytes);
        var derivedKey = DeriveKeyFromPassphrase(passphrase, keyId);

        var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var cyStream = CyStream.CreateReader(fileStream, derivedKey.AsReadOnlySpan());
        return new CyFileStream(cyStream, null, null, derivedKey);
    }

    /// <summary>Creates a new encrypted file for writing.</summary>
    /// <param name="path">The file path.</param>
    /// <param name="key">The 256-bit encryption key.</param>
    /// <param name="options">Optional file stream configuration.</param>
    public static CyFileStream CreateWrite(string path, ReadOnlySpan<byte> key, SecureFileOptions? options = null)
    {
        options ??= new SecureFileOptions();
        var keyId = Guid.NewGuid();

        string? tempPath = null;
        string targetPath;

        if (options.AtomicWrite)
        {
            tempPath = path + ".tmp." + Guid.NewGuid().ToString("N")[..8];
            targetPath = tempPath;
        }
        else
        {
            targetPath = path;
        }

        var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None);
        var cyStream = CyStream.CreateWriter(fileStream, key, keyId, options.ChunkSize, flags: options.Flags);
        return new CyFileStream(cyStream, tempPath, path, null);
    }

    /// <summary>Creates a new encrypted file for writing with a passphrase-derived key.</summary>
    /// <param name="path">The file path.</param>
    /// <param name="passphrase">The passphrase.</param>
    /// <param name="options">Optional file stream configuration.</param>
    public static CyFileStream CreateWrite(string path, string passphrase, SecureFileOptions? options = null)
    {
        options ??= new SecureFileOptions();
        var keyId = Guid.NewGuid();
        var derivedKey = DeriveKeyFromPassphrase(passphrase, keyId);

        options.Flags |= StreamSerializationFormat.StreamOption.PassphraseDerived;

        string? tempPath = null;
        string targetPath;

        if (options.AtomicWrite)
        {
            tempPath = path + ".tmp." + Guid.NewGuid().ToString("N")[..8];
            targetPath = tempPath;
        }
        else
        {
            targetPath = path;
        }

        var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None);
        var cyStream = CyStream.CreateWriter(
            fileStream, derivedKey.AsReadOnlySpan(), keyId, options.ChunkSize, flags: options.Flags);
        return new CyFileStream(cyStream, tempPath, path, derivedKey);
    }

    /// <summary>Gets the underlying <see cref="CyStream"/>.</summary>
    public CyStream Stream => _cyStream;

    /// <summary>Writes data to the encrypted file.</summary>
    public void Write(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        _cyStream.Write(data.ToArray(), 0, data.Length);
    }

    /// <summary>Reads data from the encrypted file.</summary>
    public int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        var tempBuf = new byte[buffer.Length];
        try
        {
            var read = _cyStream.Read(tempBuf, 0, tempBuf.Length);
            tempBuf.AsSpan(0, read).CopyTo(buffer);
            return read;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tempBuf);
        }
    }

    private static SecureBuffer DeriveKeyFromPassphrase(string passphrase, Guid salt)
    {
        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            var saltBytes = salt.ToByteArray();
            var keyBytes = HkdfKeyDerivation.DeriveKey(passphraseBytes, outputLength: 32, salt: saltBytes, info: PassphraseInfo);
            var key = new SecureBuffer(32);
            key.Write(keyBytes);
            CryptographicOperations.ZeroMemory(keyBytes);
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        _cyStream.Dispose();
        _derivedKey?.Dispose();

        // Atomic write: rename temp file to final path
        if (_tempPath != null && _finalPath != null && System.IO.File.Exists(_tempPath))
        {
            System.IO.File.Move(_tempPath, _finalPath, overwrite: true);
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        await _cyStream.DisposeAsync().ConfigureAwait(false);
        _derivedKey?.Dispose();

        if (_tempPath != null && _finalPath != null && System.IO.File.Exists(_tempPath))
        {
            System.IO.File.Move(_tempPath, _finalPath, overwrite: true);
        }
    }
}
