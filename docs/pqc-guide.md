# Post-Quantum Cryptography (PQC) Guide

## Overview

CyTypes includes post-quantum key encapsulation via ML-KEM-1024 (FIPS 203, NIST Level 5) through BouncyCastle. A hybrid scheme combines classical ECDH P-256 with ML-KEM-1024 for defense-in-depth: secure even if one scheme is broken.

PQC is integrated into `CyNetworkStream` and `CyPipeStream` for automatic quantum-resistant channel establishment.

## Installation

PQC is part of the core package -- no additional install needed:

```bash
dotnet add package CyTypes.Core
```

For streaming with automatic PQC key exchange:

```bash
dotnet add package CyTypes.Streams
```

## ML-KEM-1024 Key Encapsulation

### Basic KEM

`MlKemKeyEncapsulation` provides raw ML-KEM-1024 operations:

```csharp
using CyTypes.Core.Crypto.Pqc;

var mlkem = new MlKemKeyEncapsulation();

// Generate key pair
var (publicKey, secretKey) = mlkem.GenerateKeyPair();

// Sender: encapsulate a shared secret using the public key
var (ciphertext, sharedSecret) = mlkem.Encapsulate(publicKey);

// Receiver: decapsulate to recover the same shared secret
byte[] recovered = mlkem.Decapsulate(ciphertext, secretKey);
// sharedSecret == recovered (32 bytes / 256 bits)
```

### Secure Key Storage

`MlKemKeyPair` holds key material in memory with secure disposal:

```csharp
using var keyPair = new MlKemKeyPair(publicKey, secretKey);
// Key material is zeroed with CryptographicOperations.ZeroMemory on Dispose()
```

## Hybrid Key Exchange: ECDH P-256 + ML-KEM-1024

`SessionKeyNegotiator` combines classical and post-quantum key exchange for a hybrid session key derived via HKDF-SHA512.

### Protocol

```
SessionKey = HKDF-SHA512(
    ecdh_shared || mlkem_shared,
    salt = SHA512(transcript_hash),
    info = "CyTypes.SessionKey"
)
```

### Usage

```csharp
using CyTypes.Core.Crypto.KeyExchange;

// Both parties create negotiators
using var alice = new SessionKeyNegotiator();
using var bob = new SessionKeyNegotiator();

// Exchange handshake messages (contains ECDH + ML-KEM public keys)
var aliceHandshake = alice.CreateHandshake();
var bobHandshake = bob.CreateHandshake();

// Alice (initiator) derives session key
var (aliceKey, mlKemCiphertext) = alice.DeriveSessionKeyAsInitiator(bobHandshake);

// Bob (responder) derives session key using Alice's ML-KEM ciphertext
using var bobKey = bob.DeriveSessionKeyAsResponder(aliceHandshake, mlKemCiphertext);

// Both keys are identical 32-byte (256-bit) SecureBuffer instances
using (aliceKey)
{
    bool match = aliceKey.AsReadOnlySpan().SequenceEqual(bobKey.AsReadOnlySpan());
    // match == true
}
```

### Wire Protocol

`HandshakeMessage` supports binary serialization for transport:

```csharp
byte[] wire = aliceHandshake.Serialize();
var deserialized = HandshakeMessage.Deserialize(wire);
```

## Integration with Streams

`CyNetworkStream` and `CyPipeStream` perform the hybrid key exchange automatically during connection setup. When `SecurityPolicy.RequireKeyExchange` is `true`, the handshake is mandatory.

```csharp
// Server
var server = new CyNetworkServer("127.0.0.1", 9000);
using var serverStream = await server.AcceptAsync();
// Handshake happens automatically

// Client
using var clientStream = await CyNetworkClient.ConnectAsync("127.0.0.1", 9000);
// Both streams now use the negotiated session key for encryption
```

## Dependency Injection

Register PQC support via DI:

```csharp
services.AddCyTypes(options =>
{
    options.EnablePqcKeyEncapsulation = true;
});

// Resolve IPqcKeyEncapsulation from the container
var kem = provider.GetRequiredService<IPqcKeyEncapsulation>();
```

## Key Sizes

| Component         | Size          |
|-------------------|---------------|
| ML-KEM public key | ~1,590 bytes  |
| ML-KEM secret key | ~3,266 bytes  |
| ML-KEM ciphertext | ~1,568 bytes  |
| Shared secret     | 32 bytes      |
| ECDH P-256 key    | 91 bytes      |
| Session key       | 32 bytes      |

## Security Considerations

- ML-KEM-1024 targets NIST Level 5 (equivalent to AES-256 security)
- The hybrid scheme ensures security if either ECDH or ML-KEM is broken
- All key material is stored in `SecureBuffer` (pinned, locked, zeroed on dispose)
- Ephemeral keys provide forward secrecy per session
