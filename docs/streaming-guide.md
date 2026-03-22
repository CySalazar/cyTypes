# Streaming Encryption Guide

## Overview

The `CyTypes.Streams` package provides AES-256-GCM chunked stream encryption for files, named pipes (IPC), and TCP network connections. All stream types zero plaintext buffers on disposal and support both sync and async patterns.

## Stream Types

| Class             | Transport         | Key Exchange                  |
|-------------------|-------------------|-------------------------------|
| `CyStream`        | Any `Stream`      | Manual (caller provides key)  |
| `CyFileStream`    | `FileStream`      | Manual or passphrase-derived  |
| `CyPipeStream`    | Named pipes (IPC) | Hybrid ECDH P-256 + ML-KEM-1024  |
| `CyNetworkStream` | TCP sockets       | Hybrid ECDH P-256 + ML-KEM-1024  |

## CyStream (Base)

`CyStream` wraps any .NET `Stream` with chunked AES-256-GCM encryption.

```csharp
using CyTypes.Streams;

// Write encrypted data
byte[] key = RandomNumberGenerator.GetBytes(32);
await using var writer = CyStream.CreateWriter(outputStream, key, Guid.NewGuid(), chunkSize: 65536);
writer.Write(plaintext, 0, plaintext.Length);
writer.WriteFinal(); // writes final chunk + HMAC footer

// Read encrypted data
await using var reader = CyStream.CreateReader(inputStream, key);
var buffer = new byte[4096];
int bytesRead;
while ((bytesRead = reader.Read(buffer, 0, buffer.Length)) > 0)
{
    Process(buffer.AsSpan(0, bytesRead));
}
```

## Chunked Encryption

Data is split into fixed-size chunks (configurable via `StreamChunkSize` in `SecurityPolicy`). Each chunk is independently encrypted with AES-256-GCM using a unique nonce derived from the sequence number. The stream format is:

1. **Header** -- magic bytes, key ID, chunk size, flags
2. **Chunks** -- `[length:4][encrypted_data + nonce + GCM_tag]` repeated
3. **Footer** -- chunk count + HMAC-SHA512 over header and all GCM tags

The HMAC key is derived from the stream key via HKDF.

## File Streams

`CyFileStream` adds file-specific features: atomic writes (temp file + rename) and passphrase-derived keys.

```csharp
using CyTypes.Streams.File;

// Write with a raw key
byte[] key = RandomNumberGenerator.GetBytes(32);
using var writer = CyFileStream.CreateWrite("/tmp/secret.dat", key,
    new SecureFileOptions { AtomicWrite = true, ChunkSize = 65536 });
writer.Write(data);

// Read with a passphrase (key derived via HKDF from passphrase + salt)
using var reader = CyFileStream.OpenRead("/tmp/secret.dat", "my-passphrase");
var buffer = new byte[4096];
int read = reader.Read(buffer);
```

Atomic writes ensure that a crash during write does not corrupt the original file.

### SecureFileOptions Reference

| Property      | Type           | Default  | Description                                      |
|---------------|----------------|----------|--------------------------------------------------|
| `ChunkSize`   | `int`          | 65536    | Plaintext chunk size in bytes                    |
| `Passphrase`  | `string?`      | `null`   | Optional passphrase for HKDF key derivation      |
| `Flags`       | `StreamOption` | `None`   | Stream flags (see below)                         |
| `AtomicWrite` | `bool`         | `true`   | Write to temp file, rename on dispose            |

### StreamOption Flags

| Flag                | Value | Description                                        |
|---------------------|-------|----------------------------------------------------|
| `None`              | 0     | No flags set                                       |
| `PassphraseDerived` | 1     | The stream key was derived from a passphrase       |
| `KeyExchange`       | 2     | The stream uses key exchange for session negotiation|

Flags are set automatically when using passphrase-based or key-exchange constructors. They are persisted in the stream header for correct deserialization on read.

## IPC Streams (Named Pipes)

`CyPipeServer` and `CyPipeClient` provide encrypted inter-process communication.
Session keys are negotiated via hybrid key exchange (ECDH P-256 + ML-KEM-1024).

```csharp
using CyTypes.Streams.Ipc;

// Server
var server = new CyPipeServer("my-secure-pipe");
using var serverStream = await server.AcceptAsync(); // handshake happens automatically

var data = await serverStream.ReceiveAsync();
await serverStream.SendAsync(responseBytes);

// Client
var client = new CyPipeClient("my-secure-pipe");
using var clientStream = await client.ConnectAsync();

await clientStream.SendAsync(requestBytes);
var response = await clientStream.ReceiveAsync();
```

## Network Streams (TCP)

`CyNetworkServer` and `CyNetworkClient` provide encrypted TCP communication with the same hybrid key exchange as IPC.

```csharp
using CyTypes.Streams.Network;

// Server
var server = new CyNetworkServer(port: 9443);
using var stream = await server.AcceptAsync(); // handshake included

stream.HeartbeatInterval = TimeSpan.FromSeconds(30);
stream.ReceiveTimeout = TimeSpan.FromSeconds(60);

var data = await stream.ReceiveAsync();
await stream.SendAsync(responseBytes);
await stream.CloseAsync(); // graceful close frame

// Client
var client = new CyNetworkClient("localhost", 9443);
using var stream = await client.ConnectAsync();

await stream.SendAsync(requestBytes);
var response = await stream.ReceiveAsync();
```

## Session Key Negotiation

IPC and network streams use `SessionKeyNegotiator` for hybrid post-quantum key exchange:

1. Both sides generate ephemeral ECDH P-256 and ML-KEM-1024 key pairs
2. Public keys are exchanged in `HandshakeMessage` frames
3. The initiator encapsulates the ML-KEM shared secret
4. Both sides derive: `HKDF-SHA512(ecdh_shared || mlkem_shared, salt=transcript_hash, info="CyTypes.SessionKey")`

The transcript hash uses canonical (sorted) key ordering so both sides produce identical session keys.

## Configuration via Policy

Stream behavior is controlled by `SecurityPolicy` properties:

| Property            | Description                                | Default (Balanced) |
|---------------------|--------------------------------------------|--------------------|
| `StreamChunkSize`   | Plaintext bytes per chunk                  | 65536              |
| `RequireKeyExchange`| Require key negotiation for IPC/network    | true               |
| `StreamIntegrity`   | `PerChunkPlusFooter` or `PerChunkOnly`     | `PerChunkPlusFooter`|
