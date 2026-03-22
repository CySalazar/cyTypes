# Security Model

## Threat Model

CyTypes protects against:

- **Memory inspection** -- values are AES-256-GCM encrypted in pinned buffers; plaintext exists only transiently during operations and is zeroed promptly (see Known Limitations for GC caveats)
- **Cold boot / swap attacks** -- `PinnedLocked` and `PinnedLockedReEncrypting` memory protection prevents paging to disk via `mlock`
- **Accidental logging** -- `ToString()` always returns a redacted representation; `FormattingMode.Redacted` is the default
- **Over-decryption** -- configurable `MaxDecryptionCount` and `DecryptionRateLimit` limit how often plaintext is extracted
- **Taint propagation** -- operations between values with different policies are tracked and controlled
- **Key compromise window** -- automatic key rotation re-encrypts data on a configurable schedule

## Encryption at Rest

All values are encrypted using **AES-256-GCM** via `AesGcmEngine`. Each encryption produces a unique nonce and authentication tag. The ciphertext, nonce, and tag are stored together in a `SecureBuffer`.

Key material is derived per-instance using HKDF-SHA512 (`HkdfKeyDerivation`). Each `CyTypeBase<TSelf, TNative>` instance owns its own `KeyManager` with independent key material.

## Key Management

- **Per-instance keys** -- every CyType instance generates its own 256-bit encryption key
- **HKDF derivation** -- keys are derived via HKDF-SHA512 with unique salt and context info
- **Key rotation** -- `RotateKeyAndReEncrypt()` atomically derives a new key and re-encrypts the value
- **TTL support** -- `KeyRotationPolicy.EveryNOperations(n)` or `KeyRotationPolicy.EveryNMinutes(n)` trigger automatic rotation
- **Platform key store** -- `PlatformKeyStore` supports `InMemoryOnly` and `OsProtected` capability levels

## Memory Protection

Three levels are available via the `MemoryProtection` enum:

| Level                       | Behavior                                                |
|-----------------------------|---------------------------------------------------------|
| `PinnedLockedReEncrypting`  | Pinned + mlock + periodic re-encryption with fresh keys |
| `PinnedLocked`              | Pinned + mlock to prevent swapping                      |
| `PinnedOnly`                | Pinned in memory; no OS-level lock                      |

All `SecureBuffer` instances zero their contents on disposal via `CryptographicOperations.ZeroMemory`. Plaintext byte arrays created during encrypt/decrypt are zeroed in `finally` blocks.

## Taint Tracking and Compromise Detection

Each instance tracks two independent flags via `SecurityContext`:

- **Compromised** -- set when `ToInsecureValue()` is called (plaintext escapes the enclave). Irreversible.
- **Tainted** -- set when a value interacts with a weaker policy or undergoes demotion. Can be cleared with `ClearTaint(reason)`.

The `TaintMode` enum controls cross-policy behavior:

| Mode       | Behavior                                                          |
|------------|-------------------------------------------------------------------|
| `Strict`   | Cross-policy operations throw `PolicyViolationException`          |
| `Standard` | Taint propagates through operations using standard rules          |
| `Relaxed`  | Minimal tracking, no cross-policy restrictions                    |

## Constant-Time Comparisons

When `ComparisonMode.HmacBased` is active, equality checks use HMAC-derived tags compared via `CryptographicOperations.FixedTimeEquals` (in `HmacComparer`). This prevents timing side-channels on equality operations.

## Auto-Destroy

When `AutoDestroy = true` and `MaxDecryptionCount` is reached, the instance automatically disposes itself, zeroing all buffers and keys. The `SecurityBreached` event fires before destruction.

## Known Limitations

- **Metadata leaks** -- `CyString.Length` is stored as unencrypted metadata. An attacker with memory access can infer string length. Use `SecureLength` (which decrypts) or fixed-length padding if length must be hidden.
- **GC pressure** -- encrypt/decrypt cycles allocate temporary byte arrays. These are zeroed promptly, but GC may compact memory before zeroing completes on very short-lived arrays.
- **No SGX/TEE integration** -- "SecureEnclave" mode uses in-process isolation (decrypt-operate-reencrypt), not hardware enclaves.
- **FHE ciphertext size** -- homomorphic ciphertexts are orders of magnitude larger than AES ciphertexts. Monitor noise budgets.
