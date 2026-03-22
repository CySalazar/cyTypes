# Policy Reference

## Predefined Policies

### `SecurityPolicy.Maximum`

Highest security. Checked arithmetic, strict taint, HMAC comparison, auto-destroy after 10 decryptions, rate-limited to 10/sec, OS-protected key store required.

| Component         | Value                                |
|-------------------|--------------------------------------|
| Arithmetic        | `SecureEnclave`                      |
| Comparison        | `HmacBased`                          |
| StringOperations  | `SecureEnclave`                      |
| Memory            | `PinnedLockedReEncrypting`           |
| KeyRotation       | `EveryNOperations(100)`              |
| Audit             | `AllOperations`                      |
| Taint             | `Strict`                             |
| MaxDecryptionCount| 10                                   |
| AutoDestroy       | true                                 |
| DecryptionRateLimit| 10                                  |
| Overflow          | `Checked`                            |
| StreamChunkSize   | 4096                                 |
| StreamIntegrity   | `PerChunkPlusFooter`                 |

### `SecurityPolicy.Balanced` (Default)

Good balance of security and usability. Default for all CyType instances.

| Component         | Value                                |
|-------------------|--------------------------------------|
| Arithmetic        | `SecureEnclave`                      |
| Comparison        | `HmacBased`                          |
| StringOperations  | `SecureEnclave`                      |
| Memory            | `PinnedLocked`                       |
| KeyRotation       | `EveryNOperations(1000)`             |
| Audit             | `DecryptionsAndTransfers`            |
| Taint             | `Standard`                           |
| MaxDecryptionCount| 100                                  |
| AutoDestroy       | false                                |
| Overflow          | `Unchecked`                          |
| StreamChunkSize   | 65536                                |
| StreamIntegrity   | `PerChunkPlusFooter`                 |

### `SecurityPolicy.Performance`

Minimal overhead for high-throughput scenarios.

| Component         | Value                                |
|-------------------|--------------------------------------|
| Arithmetic        | `SecureEnclave`                      |
| Comparison        | `SecureEnclave`                      |
| StringOperations  | `SecureEnclave`                      |
| Memory            | `PinnedOnly`                         |
| KeyRotation       | `Manual`                             |
| Audit             | `CompromiseOnly`                     |
| Taint             | `Relaxed`                            |
| MaxDecryptionCount| `int.MaxValue`                       |
| AutoDestroy       | false                                |
| StreamChunkSize   | 262144                               |
| StreamIntegrity   | `PerChunkOnly`                       |

### `SecurityPolicy.HomomorphicBasic`

Enables FHE arithmetic (add, subtract, multiply) on integer types via Microsoft SEAL BFV.

| Component         | Value                                |
|-------------------|--------------------------------------|
| Arithmetic        | `HomomorphicBasic`                   |
| Comparison        | `HmacBased`                          |
| Memory            | `PinnedLocked`                       |
| KeyRotation       | `EveryNOperations(1000)`             |
| Audit             | `DecryptionsAndTransfers`            |
| Taint             | `Standard`                           |
| MaxDecryptionCount| 1000                                 |

### `SecurityPolicy.HomomorphicFull`

Enables full FHE stack: homomorphic arithmetic, homomorphic comparisons via encrypted difference, and deterministic string equality via AES-SIV. Requires `AllOperations` audit level.

| Component         | Value                                |
|-------------------|--------------------------------------|
| Arithmetic        | `HomomorphicFull`                    |
| Comparison        | `HomomorphicCircuit`                 |
| StringOperations  | `HomomorphicEquality`                |
| Memory            | `PinnedLocked`                       |
| KeyRotation       | `EveryNOperations(1000)`             |
| Audit             | `AllOperations`                      |
| Taint             | `Standard`                           |
| MaxDecryptionCount| 1000                                 |

## Policy Components

### ArithmeticMode
- `HomomorphicFull` -- full FHE arithmetic with homomorphic comparisons and deterministic string equality
- `HomomorphicBasic` -- add, subtract, multiply on encrypted integers via SEAL BFV
- `SecureEnclave` -- decrypt, compute, re-encrypt in-process

### ComparisonMode
- `HomomorphicCircuit` -- encrypted difference with deferred sign extraction (subtraction is homomorphic; verdict requires decryption)
- `HmacBased` -- constant-time HMAC tag comparison
- `SecureEnclave` -- decrypt and compare in-process

### StringOperationMode
- `HomomorphicEquality` -- encrypted equality test via AES-SIV deterministic encryption (not FHE)
- `SecureEnclave` -- decrypt and operate in-process

### MemoryProtection
- `PinnedLockedReEncrypting` -- pinned + mlock + periodic re-encryption
- `PinnedLocked` -- pinned + mlock
- `PinnedOnly` -- pinned only

### TaintMode
- `Strict` -- blocks cross-policy operations unless explicitly allowed
- `Standard` -- propagates taint through operations
- `Relaxed` -- minimal taint tracking

### AuditLevel
- `AllOperations` -- log every operation
- `DecryptionsAndTransfers` -- log decryptions and data transfers
- `CompromiseOnly` -- log only compromise/violation events
- `None` -- no audit logging

### KeyRotationPolicy
- `EveryNOperations(n)` -- rotate after N operations
- `EveryNMinutes(n)` -- rotate after N minutes
- `Manual` -- caller must rotate explicitly

### OverflowMode
- `Checked` -- throw `OverflowException` on integer overflow
- `Unchecked` -- silently wrap (default .NET behavior)

### FormattingMode
- `Redacted` -- `IFormattable.ToString()` returns redacted output (default)
- `AllowFormatted` -- allows formatted output, marks instance as compromised

### StreamIntegrityMode
- `PerChunkPlusFooter` -- GCM tag per chunk + HMAC-SHA512 footer
- `PerChunkOnly` -- GCM tag per chunk, no footer

### CharAccessMode
- `CompromiseOnAccess` -- accessing a `CyString` character via indexer marks the instance as compromised (default)
- `TaintOnAccess` -- accessing a character marks the instance as tainted instead of compromised

## Policy Resolution

When two CyType values with different policies interact (e.g., `a + b`), `PolicyResolver.Resolve()` produces a combined policy by picking the **most restrictive** setting for each component:

1. **Security level** -- lower enum ordinal (more secure) wins
2. **Taint** -- stricter mode wins
3. **Audit** -- more verbose level wins
4. **Key rotation** -- more frequent rotation wins
5. **Memory** -- stronger protection wins

Use `PolicyResolver.Explain()` for diagnostic output showing how each component was resolved.

## Custom Policies

```csharp
var policy = new SecurityPolicyBuilder()
    .WithName("FinancialData")
    .WithArithmeticMode(ArithmeticMode.SecureEnclave)
    .WithComparisonMode(ComparisonMode.HmacBased)
    .WithMemoryProtection(MemoryProtection.PinnedLockedReEncrypting)
    .WithKeyRotation(KeyRotationPolicy.EveryNOperations(500))
    .WithAuditLevel(AuditLevel.AllOperations)
    .WithTaintMode(TaintMode.Strict)
    .WithMaxDecryptionCount(50)
    .WithDecryptionRateLimit(5)
    .WithOverflowMode(OverflowMode.Checked)
    .WithAutoDestroy(true)
    .Build();
```

The builder validates constraints at `Build()` time (e.g., FHE modes require `PinnedLocked`, strict taint requires audit level >= `DecryptionsAndTransfers`).
