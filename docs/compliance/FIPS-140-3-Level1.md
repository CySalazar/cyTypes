# FIPS 140-3 Level 1 Self-Assessment — cyTypes

> **Disclaimer**: This document provides a self-assessment of alignment with
> FIPS 140-3 Level 1 requirements. Formal certification requires submission
> to a CMVP-accredited laboratory and costs $50k-$200k+.

## Cryptographic Boundary
The cryptographic module boundary encompasses:
- `CyTypes.Core.Crypto.AesGcmEngine` — AES-256-GCM encryption/decryption
- `CyTypes.Core.Crypto.HkdfKeyDerivation` — HKDF-SHA512 key derivation
- `CyTypes.Core.Crypto.HmacComparer` — HMAC-SHA512 authentication
- `CyTypes.Core.Memory.SecureBuffer` — Secure key storage with zeroing
- `CyTypes.Core.KeyManagement.KeyManager` — Key lifecycle management

## Approved Algorithms

| Algorithm | Standard | Key/Output Size | Implementation |
|-----------|----------|-----------------|----------------|
| AES-256-GCM | FIPS 197 + SP 800-38D | 256-bit key, 128-bit tag | .NET `AesGcm` |
| HKDF-SHA512 | RFC 5869 / SP 800-56C | Variable | .NET `HKDF` |
| HMAC-SHA512 | FIPS 198-1 | 512-bit output | .NET `HMACSHA512` |
| CSPRNG | SP 800-90A | N/A | .NET `RandomNumberGenerator` |

## Known Answer Tests (KAT)
Self-tests implemented in `KnownAnswerSelfTests.cs`:
- AES-256-GCM: Decrypt with fixed key/nonce/ciphertext/tag
- HKDF-SHA512: DeriveKey with fixed IKM/salt/info
- HMAC-SHA512: Compute with fixed key/data

## Key Management
- Keys are 256-bit, generated via CSPRNG
- Keys are stored in pinned memory (`SecureBuffer`)
- Key zeroing on disposal via `CryptographicOperations.ZeroMemory`
- Optional OS-level memory locking (mlock/VirtualLock)
- Key rotation via TTL-based policy (`KeyManager`)

## Physical Security (Level 1)
FIPS 140-3 Level 1 has no physical security requirements.
The module runs as a software library within the .NET runtime.

## Operational Environment
- .NET 9.0 runtime on Linux/Windows/macOS
- No hardware security module (HSM) required
- Platform key storage via OS keychains (optional)
