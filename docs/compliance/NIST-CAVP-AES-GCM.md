# NIST CAVP AES-GCM Mapping — cyTypes

## Algorithm Implementation
- **Algorithm**: AES-256-GCM (AEAD)
- **Key Size**: 256 bits
- **Nonce Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Implementation**: `CyTypes.Core.Crypto.AesGcmEngine`

## CAVP Test Categories Coverage

| CAVP Category | Test Method | Status |
|--------------|-------------|--------|
| GCM Encrypt | Roundtrip tests via `EncryptionBenchmarks` | Covered |
| GCM Decrypt | Wycheproof `aes_gcm_test.json` vectors | Covered |
| GCM AE | Known Answer Self-Tests (`KnownAnswerSelfTests.cs`) | Covered |
| Invalid Tag | Wycheproof invalid vectors, tamper tests | Covered |
| Key Length | OWASP compliance test (`OwaspCryptoComplianceTests.cs`) | Covered |

## Wycheproof Vector Coverage
- Source: Google Wycheproof Project (`aes_gcm_test.json`)
- Filter: `keySize=256, ivSize=96, tagSize=128`
- Valid vectors: Decrypt and verify plaintext matches expected
- Invalid vectors: Verify `CryptographicException` is thrown

## Implementation Notes
- Nonces are generated via `RandomNumberGenerator.Fill()` (CSPRNG)
- Output format: `[nonce:12][ciphertext:N][tag:16]`
- The engine delegates to .NET's `System.Security.Cryptography.AesGcm`
- Encrypt operations use random nonces and are therefore non-deterministic

## Limitations
- Formal CAVP certification requires submission to NIST CMVP lab
- This document maps test coverage to CAVP categories for compliance alignment
