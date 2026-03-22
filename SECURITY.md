# Security Policy

> Maintained by Matteo Sala (cysalazar@cysalazar.com)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

We take the security of cyTypes seriously. If you discover a security vulnerability, please report it responsibly.

**Email:** security@cysalazar.com

**Expected response time:** 48 hours

**What to include in your report:**

- A clear description of the vulnerability
- Steps to reproduce the issue
- The potential impact or severity
- Any suggested mitigations or fixes
- Your name/handle for credit (optional)

Please do not open a public issue for security vulnerabilities. We will acknowledge your report within 48 hours and work with you to understand and address the issue before any public disclosure.

## Security Guarantees

cyTypes provides the following security guarantees:

- **AES-256-GCM encryption at rest** -- All sensitive data is encrypted using AES-256 in GCM mode, providing both confidentiality and authenticity.
- **HKDF-SHA512 key derivation** -- Keys are derived using HKDF with SHA-512, ensuring cryptographically strong key material.
- **Pinned + locked memory buffers** -- Sensitive data is held in pinned and locked memory to prevent swapping to disk and reduce exposure in memory.
- **Thread-safe dispose** -- `SecureBuffer.Dispose()` uses `Interlocked.CompareExchange` for atomic state transition, preventing double-free and use-after-free under concurrent access. Accessors (`AsSpan`, `ToArray`, `Write`) check the dispose flag atomically.
- **Volatile security flags** -- `SecurityContext` flags (`IsCompromised`, `IsTainted`, `IsAutoDestroyed`) use `Volatile.Read`/`Interlocked.Exchange` to guarantee cross-thread visibility without full locking.
- **Ciphertext copy zeroing** -- `DecryptValue()` zeroes both the ciphertext copy and the plaintext buffer in a `finally` block, ensuring cleanup even when decryption throws an exception.
- **Atomic key rotation** -- `RotateKeyAndReEncrypt()` decrypts with the current key, derives a new key via HKDF, and re-encrypts in a single operation. Calling `KeyManager.RotateKey()` directly destroys the old key and is intentionally not exposed as a public API.
- **Constant-time comparison via FixedTimeEquals** -- All equality checks on sensitive data use constant-time algorithms to prevent timing side-channel attacks.
- **Checked integer arithmetic** -- The `Maximum` policy uses `OverflowMode.Checked` to detect integer overflow attacks. Custom policies can opt-in via `WithOverflowMode(OverflowMode.Checked)`.
- **Input size validation** -- `CyString` and `CyBytes` enforce a 16 MB maximum payload size at construction, consistent with deserialization limits.

## Timing Safety

- The `==` operator on `CyString` uses constant-time comparison internally, making it safe for use in security-sensitive contexts.
- For explicit security-critical comparisons, use the `SecureEquals()` method to clearly signal intent and guarantee constant-time behavior.
- The `Length` property is available without decryption. It reads metadata only and does not expose plaintext or timing information.

## Metadata Exposure

- **CyString.Length** and **CyBytes.Length** are stored as unencrypted metadata for performance. An attacker with access to the object instance can infer the plaintext size. If length confidentiality is required, apply fixed-length padding before encryption.
- **CyTypeBase.ToString()** returns `[TypeName:Encrypted|Policy=...|Compromised=...]` — no plaintext is ever included in string representations. The `RedactingLogger` provides an additional safety net for log output.

## FHE and PQC Status

- **FHE (Phase 3a+3b — Complete):** The `CyTypes.Fhe` package provides `SealBfvEngine` for exact integer arithmetic and `SealCkksEngine` for approximate floating-point arithmetic on encrypted data. `SecurityPolicyBuilder` accepts `HomomorphicBasic` and `HomomorphicFull` arithmetic modes. `ComparisonMode.HomomorphicCircuit` enables homomorphic comparisons via encrypted difference with deferred sign extraction (`SealComparisonEngine`). `StringOperationMode.HomomorphicEquality` uses AES-SIV (RFC 5297) deterministic encryption for encrypted string equality checks. **CKKS precision note:** CKKS uses approximate arithmetic with ~15 significant digits; `decimal`'s 28-29 digit precision is not preserved through FHE operations. **AES-SIV security note:** Deterministic encryption intentionally leaks equality patterns (same plaintext → same ciphertext). This is IND-CPA secure but not IND-CCA2; use only for equality checks, not general-purpose encryption.
- **PQC (Phase 3c — Complete):** `MlKemKeyEncapsulation` provides full ML-KEM-1024 (FIPS 203) key encapsulation via BouncyCastle. `SessionKeyNegotiator` implements hybrid ECDH P-256 + ML-KEM-1024 key exchange with HKDF-SHA512 session key derivation. Integrated into `CyNetworkStream` (TCP) and `CyPipeStream` (named pipes) for automatic post-quantum secure channel establishment.

## Known Limitations

- Integer arithmetic uses unchecked mode by default (matching native .NET behavior). Use `OverflowMode.Checked` or the `Maximum` policy for overflow protection.
- No key export/import — key material cannot be serialized out of process. This is an intentional security decision.
- Memory locking (`mlock`/`VirtualLock`) may silently fail on platforms with restricted limits. Encryption and zeroing still apply.
