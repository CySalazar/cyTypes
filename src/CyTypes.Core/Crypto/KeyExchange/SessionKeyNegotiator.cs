using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CyTypes.Core.Crypto.Pqc;
using CyTypes.Core.Memory;

namespace CyTypes.Core.Crypto.KeyExchange;

/// <summary>
/// Hybrid key exchange combining ECDH P-256 and ML-KEM-1024 (post-quantum).
/// The session key is derived as:
/// <c>HKDF-SHA512(ecdh_shared || mlkem_shared, salt=transcript_hash, info="CyTypes.SessionKey")</c>.
/// </summary>
public sealed class SessionKeyNegotiator : IDisposable
{
    private static readonly byte[] SessionKeyInfo = Encoding.UTF8.GetBytes("CyTypes.SessionKey");

    private readonly ECDiffieHellman _ecdh;
    private readonly MlKemKeyEncapsulation _mlKem;
    private byte[]? _mlKemPublicKey;
    private byte[]? _mlKemSecretKey;
    private int _isDisposed; // 0 = alive, 1 = disposed (atomic via Interlocked)

    /// <summary>Gets the ECDH P-256 public key bytes (SubjectPublicKeyInfo DER).</summary>
    public byte[] EcdhPublicKey { get; }

    /// <summary>Gets the ML-KEM-1024 public key bytes.</summary>
    public byte[] MlKemPublicKey => _mlKemPublicKey ?? throw new InvalidOperationException("Key pair not generated.");

    /// <summary>
    /// Initializes a new <see cref="SessionKeyNegotiator"/> and generates ephemeral key pairs.
    /// </summary>
    public SessionKeyNegotiator()
    {
        _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            _mlKem = new MlKemKeyEncapsulation();

            EcdhPublicKey = _ecdh.PublicKey.ExportSubjectPublicKeyInfo();

            var (pub, sec) = _mlKem.GenerateKeyPair();
            _mlKemPublicKey = pub;
            _mlKemSecretKey = sec;
        }
        catch
        {
            _ecdh.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a <see cref="HandshakeMessage"/> to send to the peer.
    /// </summary>
    public HandshakeMessage CreateHandshake()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        return new HandshakeMessage(EcdhPublicKey, MlKemPublicKey);
    }

    /// <summary>
    /// Initiator side: encapsulates shared secrets using the responder's public keys
    /// and derives a session key.
    /// </summary>
    /// <param name="responderHandshake">The responder's handshake message containing their public keys.</param>
    /// <returns>The derived 32-byte session key and the ML-KEM ciphertext to send to the responder.</returns>
    public (SecureBuffer SessionKey, byte[] MlKemCiphertext) DeriveSessionKeyAsInitiator(HandshakeMessage responderHandshake)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);

        // ECDH P-256 shared secret
        using var peerEcdh = ECDiffieHellman.Create();
        peerEcdh.ImportSubjectPublicKeyInfo(responderHandshake.EcdhPublicKey, out _);
        var ecdhShared = _ecdh.DeriveKeyMaterial(peerEcdh.PublicKey);

        // ML-KEM encapsulation
        var (mlKemCiphertext, mlKemShared) = _mlKem.Encapsulate(responderHandshake.MlKemPublicKey);

        try
        {
            return (DeriveSessionKey(ecdhShared, mlKemShared, responderHandshake), mlKemCiphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ecdhShared);
            CryptographicOperations.ZeroMemory(mlKemShared);
        }
    }

    /// <summary>
    /// Responder side: decapsulates the ML-KEM ciphertext and derives the session key.
    /// </summary>
    /// <param name="initiatorHandshake">The initiator's handshake message.</param>
    /// <param name="mlKemCiphertext">The ML-KEM ciphertext from the initiator.</param>
    /// <returns>The derived 32-byte session key.</returns>
    public SecureBuffer DeriveSessionKeyAsResponder(HandshakeMessage initiatorHandshake, byte[] mlKemCiphertext)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);

        if (_mlKemSecretKey == null)
            throw new InvalidOperationException("ML-KEM secret key not available.");

        // ECDH P-256 shared secret
        using var peerEcdh = ECDiffieHellman.Create();
        peerEcdh.ImportSubjectPublicKeyInfo(initiatorHandshake.EcdhPublicKey, out _);
        var ecdhShared = _ecdh.DeriveKeyMaterial(peerEcdh.PublicKey);

        // ML-KEM decapsulation
        var mlKemShared = _mlKem.Decapsulate(mlKemCiphertext, _mlKemSecretKey);

        try
        {
            return DeriveSessionKey(ecdhShared, mlKemShared, initiatorHandshake);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ecdhShared);
            CryptographicOperations.ZeroMemory(mlKemShared);
        }
    }

    private SecureBuffer DeriveSessionKey(byte[] ecdhShared, byte[] mlKemShared, HandshakeMessage peerHandshake)
    {
        // SECURITY: All intermediate buffers are zeroed in finally blocks to prevent leaks
        byte[]? combined = null;
        byte[]? transcript = null;
        byte[]? salt = null;
        try
        {
            // Combine shared secrets
            combined = new byte[ecdhShared.Length + mlKemShared.Length];
            ecdhShared.CopyTo(combined, 0);
            mlKemShared.CopyTo(combined, ecdhShared.Length);

            // Transcript hash uses canonical (sorted) key ordering so both sides produce the same hash.
            // Sort: smaller ECDH key first, then smaller ML-KEM key first.
            var (ecdhFirst, ecdhSecond) = OrderByContent(EcdhPublicKey, peerHandshake.EcdhPublicKey);
            var (mlKemFirst, mlKemSecond) = OrderByContent(MlKemPublicKey, peerHandshake.MlKemPublicKey);

            transcript = new byte[ecdhFirst.Length + ecdhSecond.Length +
                                      mlKemFirst.Length + mlKemSecond.Length];
            var offset = 0;
            ecdhFirst.CopyTo(transcript, offset); offset += ecdhFirst.Length;
            ecdhSecond.CopyTo(transcript, offset); offset += ecdhSecond.Length;
            mlKemFirst.CopyTo(transcript, offset); offset += mlKemFirst.Length;
            mlKemSecond.CopyTo(transcript, offset);

            salt = SHA512.HashData(transcript);

            var keyBytes = HkdfKeyDerivation.DeriveKey(combined, outputLength: 32, salt: salt, info: SessionKeyInfo);
            var sessionKey = new SecureBuffer(32);
            sessionKey.Write(keyBytes);
            CryptographicOperations.ZeroMemory(keyBytes);
            return sessionKey;
        }
        finally
        {
            if (combined != null) CryptographicOperations.ZeroMemory(combined);
            if (transcript != null) CryptographicOperations.ZeroMemory(transcript);
            if (salt != null) CryptographicOperations.ZeroMemory(salt);
        }
    }

    private static (byte[] First, byte[] Second) OrderByContent(byte[] a, byte[] b)
    {
        var cmp = a.AsSpan().SequenceCompareTo(b);
        return cmp <= 0 ? (a, b) : (b, a);
    }

    /// <summary>Disposes the negotiator and zeros all key material.</summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0) return;

        _ecdh.Dispose();

        if (_mlKemSecretKey != null)
        {
            CryptographicOperations.ZeroMemory(_mlKemSecretKey);
            _mlKemSecretKey = null;
        }
        if (_mlKemPublicKey != null)
        {
            _mlKemPublicKey = null;
        }
    }
}

/// <summary>Wire protocol version constants.</summary>
public static class ProtocolVersion
{
    /// <summary>Legacy handshake without version field.</summary>
    public const byte Legacy = 0;
    /// <summary>V2: adds version byte, capabilities bitmap, and frame HMAC support.</summary>
    public const byte V2 = 1;
    /// <summary>The current protocol version used by this build.</summary>
    public const byte Current = V2;
    /// <summary>First-byte values >= this threshold indicate a legacy (unversioned) handshake.</summary>
    internal const byte LegacyDetectionThreshold = 0x20;
}

/// <summary>Capabilities bitmap negotiated during handshake.</summary>
[Flags]
public enum ProtocolCapabilities : ushort
{
    /// <summary>No additional capabilities.</summary>
    None = 0,
    /// <summary>Supports HMAC-SHA256 frame authentication post-handshake.</summary>
    FrameHmac = 1,
}

/// <summary>
/// Contains the public keys and protocol metadata exchanged during a handshake.
/// </summary>
public sealed record HandshakeMessage(
    byte[] EcdhPublicKey,
    byte[] MlKemPublicKey,
    byte Version = ProtocolVersion.Current,
    ProtocolCapabilities Capabilities = ProtocolCapabilities.FrameHmac)
{
    /// <summary>
    /// Serializes the handshake message.
    /// V2 layout: [version:1][capabilities:2][ecdhKeyLen:4][ecdhKey:N][mlKemKey:M]
    /// </summary>
    public byte[] Serialize()
    {
        var output = new byte[1 + 2 + 4 + EcdhPublicKey.Length + MlKemPublicKey.Length];
        output[0] = Version;
        BinaryPrimitives.WriteUInt16LittleEndian(output.AsSpan(1, 2), (ushort)Capabilities);
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(3, 4), EcdhPublicKey.Length);
        EcdhPublicKey.CopyTo(output, 7);
        MlKemPublicKey.CopyTo(output, 7 + EcdhPublicKey.Length);
        return output;
    }

    /// <summary>Deserializes a handshake message, auto-detecting legacy vs versioned format.</summary>
    public static HandshakeMessage Deserialize(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
            throw new ArgumentException("Handshake data is too short.", nameof(data));

        // Detect legacy format: first byte >= 0x20 means it's the low byte of LE ecdhKeyLen
        if (data[0] >= ProtocolVersion.LegacyDetectionThreshold)
            return DeserializeLegacy(data);

        return DeserializeVersioned(data);
    }

    private static HandshakeMessage DeserializeLegacy(ReadOnlySpan<byte> data)
    {
        var ecdhLen = BitConverter.ToInt32(data[..4]);
        if (ecdhLen < 32 || ecdhLen > 256)
            throw new ArgumentException($"ECDH public key length {ecdhLen} is outside valid range [32, 256].", nameof(data));
        if (data.Length < 4 + ecdhLen)
            throw new ArgumentException("Handshake data is truncated.", nameof(data));

        var ecdhKey = data.Slice(4, ecdhLen).ToArray();
        var mlKemKeyLen = data.Length - 4 - ecdhLen;
        if (mlKemKeyLen < 1184 || mlKemKeyLen > 1700)
            throw new ArgumentException($"ML-KEM public key length {mlKemKeyLen} is outside valid range [1184, 1700].", nameof(data));
        var mlKemKey = data[(4 + ecdhLen)..].ToArray();

        return new HandshakeMessage(ecdhKey, mlKemKey, ProtocolVersion.Legacy, ProtocolCapabilities.None);
    }

    private static HandshakeMessage DeserializeVersioned(ReadOnlySpan<byte> data)
    {
        if (data.Length < 7)
            throw new ArgumentException("Versioned handshake data is too short.", nameof(data));

        var version = data[0];
        var capabilities = (ProtocolCapabilities)BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(1, 2));
        var ecdhLen = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(3, 4));

        if (ecdhLen < 32 || ecdhLen > 256)
            throw new ArgumentException($"ECDH public key length {ecdhLen} is outside valid range [32, 256].", nameof(data));
        if (data.Length < 7 + ecdhLen)
            throw new ArgumentException("Versioned handshake data is truncated.", nameof(data));

        var ecdhKey = data.Slice(7, ecdhLen).ToArray();
        var mlKemKeyLen = data.Length - 7 - ecdhLen;
        if (mlKemKeyLen < 1184 || mlKemKeyLen > 1700)
            throw new ArgumentException($"ML-KEM public key length {mlKemKeyLen} is outside valid range [1184, 1700].", nameof(data));
        var mlKemKey = data[(7 + ecdhLen)..].ToArray();

        return new HandshakeMessage(ecdhKey, mlKemKey, version, capabilities);
    }
}
