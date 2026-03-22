# cyTypes Stress Test Results

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total tests** | 106 |
| **Passed** | 100 |
| **Skipped** | 6 (3 FHE placeholder, 2 FHE integration, 1 named pipe Linux) |
| **Failed** | 0 |
| **Duration** | ~1 min 20s |
| **Configuration** | 20 threads, 100 iter/thread, 5s soak |

All stress tests pass across 6 categories: concurrency, memory pressure, throughput, boundary, resilience, and cross-component integration. The library demonstrates robust thread safety, correct memory lifecycle, sustained throughput without degradation, and graceful error handling under adversarial conditions.

---

## Test Environment

| Parameter | Value |
|-----------|-------|
| **OS** | Linux 6.18.7-76061807-generic x86_64 |
| **CPU** | 13th Gen Intel Core i7-13700 |
| **RAM** | 128 GB |
| **.NET** | 9.0.310 |
| **Date** | 2026-03-22 |
| **Framework** | xUnit 2.9.3, FluentAssertions 6.12.2 |

### Stress Configuration (reduced for CI)

| Parameter | Value | Env Var |
|-----------|-------|---------|
| Concurrent threads | 20 | `STRESS_THREADS` |
| Iterations per thread | 100 | `STRESS_ITERATIONS` |
| Soak duration | 5s | `STRESS_SOAK_SECONDS` |
| Buffer allocation count | 500 | `STRESS_BUFFER_COUNT` |
| Bulk entity count | 100 | `STRESS_BULK_ENTITIES` |

---

## Methodology

Tests are implemented in `tests/CyTypes.StressTests/` using xUnit with `[Trait]` categorization for selective execution. Thread contention is maximized via `Barrier` synchronization. Memory tracking uses `GC.GetTotalMemory()` with aggressive forced collection. Throughput is measured using `Stopwatch`-based atomic counters.

### How to Reproduce

```bash
# Full suite (default config: 100 threads, 1000 iter, 30s soak)
dotnet test tests/CyTypes.StressTests --filter "Category=Stress"

# Reduced config for CI
STRESS_THREADS=20 STRESS_ITERATIONS=100 STRESS_SOAK_SECONDS=5 \
  dotnet test tests/CyTypes.StressTests

# By sub-category
dotnet test tests/CyTypes.StressTests --filter "SubCategory=Concurrency"
dotnet test tests/CyTypes.StressTests --filter "SubCategory=Boundary"
```

---

## 1. Concurrency Results

**21 tests, all passed**

| Test | Threads | Iterations | Result | Notes |
|------|---------|-----------|--------|-------|
| SecureBuffer — Massive concurrent Dispose | 20 | 1 | PASS | Atomic CAS prevents double-free |
| SecureBuffer — Concurrent alloc/dispose loop | 20 | 100 | PASS | No crash under rapid lifecycle |
| SecureBuffer — Dispose vs AsSpan race | 1 | 10,000 | PASS | Either succeeds or throws `ObjectDisposedException` |
| SecureBufferPool — High contention rent/return | 20 | 100 | PASS | No buffer loss |
| SecureBufferPool — Rent during Dispose | 20 | - | PASS | Clean `ObjectDisposedException` |
| AesGcmEngine — Concurrent encrypt/decrypt same key | 20 | 100 | PASS | All round-trips correct |
| AesGcmEngine — High frequency 1-byte payloads | 20 | 100 | PASS | No nonce collision |
| KeyManager — Concurrent rotation | 20 | - | PASS | Lock serialization works |
| KeyManager — Rotate while reading | 20 | - | PASS | Readers get valid key or expected exception |
| KeyManager — Atomic usage count | 20 | 100 | PASS | Exact total matches |
| SecurityContext — Concurrent decryption count | 20 | 100 | PASS | Atomic increment verified |
| SecurityContext — AutoDestroy fires once | 100 | - | PASS | Event fires exactly once |
| SecurityContext — Rate limit no deadlock | 20 | - | PASS | No deadlock under burst |
| CyInt — Concurrent decrypt same instance | 20 | - | PASS | All return same value |
| CyInt — Mass parallel creation (6 types) | 20 | 100 | PASS | Thousands of instances, no crash |
| CyInt — Concurrent dispose | 20 | - | PASS | Thread-safe disposal |
| CyInt — Concurrent operator overloads | 20 | 100 | PASS | No shared-state corruption |
| CyList — Concurrent add/remove (characterization) | 20 | 50 | PASS | Expected exceptions documented |
| CyDictionary — Concurrent put/get (characterization) | 20 | 50 | PASS | Expected exceptions documented |
| CyList — Dispose during iteration | 2 | - | PASS | No hang or segfault |
| CyFileStream — Concurrent readers | 20 | - | PASS | All readers get correct data |

**Key Finding**: All thread-safety mechanisms (atomic CAS, locks, `Volatile.Read`) work correctly under high contention. `CyList` and `CyDictionary` are not thread-safe by design — concurrent access throws expected exceptions but causes no crashes.

---

## 2. Memory Pressure Results

**15 tests, all passed**

| Test | Peak Memory | Delta After Cleanup | Result | Notes |
|------|-------------|-------------------|--------|-------|
| SecureBuffer — 500 alloc then dispose | +4.2 MB | +221 KB | PASS | Clean reclamation |
| SecureBuffer — 10K rapid alloc/dispose | +35 MB | +17 MB | PASS | Pinned array fragmentation within bounds |
| SecureBuffer — Various sizes (1KB-4MB) | - | 0 KB | PASS | All sizes round-trip correctly |
| SecureBufferPool — 10K reuse vs fresh | - | - | PASS | Pooled: fewer GC collections |
| SecureBufferPool — Dispose releases all | +3.5 MB | +3.5 MB | PASS | Within threshold |
| CyInt — 5000 create/dispose | +4.3 MB | +48 KB | PASS | Clean reclamation |
| All types — 10K instances (1000 per type) | +73 MB | -15 MB | PASS | GC reclaims effectively |
| CyBytes — 16 MB payload | +87 MB | - | PASS | Round-trip correct |
| CyString — 1 MB payload | +231 MB | - | PASS | Round-trip correct |
| AesGcmEngine — 16 MB payload | +340 MB | - | PASS | Round-trip correct |
| GC stress — Aggressive GC during crypto | - | 0 errors | PASS | 1000 cycles, all values correct |
| Finalizer race — Mixed dispose/finalize | - | 0 crashes | PASS | 1000 buffers, no double-free |

**Per-Type Memory Footprint** (1000 instances each):

| Type | Approx. Memory |
|------|---------------|
| CyInt | ~34 KB/1000 |
| CyLong | ~4 KB/1000 |
| CyDecimal | ~72 KB/1000 |
| CyString | ~1 KB/1000 |
| CyBytes | ~1 KB/1000 |
| CyGuid | ~1 KB/1000 |
| CyDateTime | ~1 KB/1000 |

**Key Finding**: Pinned arrays cause heap fragmentation (expected with `GC.AllocateArray(pinned: true)`), but memory is reclaimed within acceptable bounds. The `SecureBufferPool` reduces GC pressure by reusing buffers.

---

## 3. Throughput Results

**13 tests (10 passed, 3 skipped FHE)**

| Test | Ops/sec | MB/sec | Duration | Result |
|------|---------|--------|----------|--------|
| CyInt — Soak encrypt/decrypt | 39,386 ops/s | - | 5s | PASS |
| CyString — Variable length soak | 16,553 ops/s | - | 5s | PASS |
| All types — Mixed workload (10 types) | 34,123 ops/s | - | 5s | PASS |
| KeyManager — Key rotation | 12,897 rot/s | - | 0.08s | PASS |
| CyInt — RotateKeyAndReEncrypt soak | 29,539 ops/s | - | 5s | PASS |
| ChunkedCryptoEngine — 10 MB write/read | - | 196/181 MB/s | - | PASS |
| CyFileStream — 10 MB file | - | 1120/138 MB/s | - | PASS |
| ChunkedCryptoEngine — Key ratchet (2^20) | - | - | <1s | PASS |
| ML-KEM-1024 — Key generation | 1,567 pairs/s | - | 0.06s | PASS |
| ML-KEM-1024 — Encapsulate/Decapsulate | 118 cycles/s | - | 0.85s | PASS |
| FHE (BFV/CKKS) | - | - | - | SKIP |

**Throughput Degradation Check**:
- CyInt early window: 19,704 ops/s
- CyInt late window: 19,703 ops/s
- **Degradation: <0.01%** (well within 20% threshold)

**Key Finding**: Sustained throughput is stable with zero degradation. File stream write achieves 1.1 GB/s, key rotation runs at nearly 13K rotations/s. ML-KEM-1024 post-quantum key exchange operates at ~118 encapsulate/decapsulate cycles per second.

---

## 4. Boundary Results

**33 tests, all passed**

| Test | Input | Expected | Result |
|------|-------|----------|--------|
| CyInt | int.MinValue (-2,147,483,648) | Round-trip | PASS |
| CyInt | int.MaxValue (2,147,483,647) | Round-trip | PASS |
| CyInt | 0, -1, 1 | Round-trip | PASS |
| CyLong | long.MinValue, MaxValue, 0 | Round-trip | PASS |
| CyDecimal | MinValue, MaxValue, Zero, One, MinusOne | Round-trip | PASS |
| CyDouble | NaN, +Inf, -Inf, Epsilon, Min, Max | Round-trip | PASS |
| CyFloat | NaN, +Inf, -Inf, Epsilon, Min, Max | Round-trip | PASS |
| CyBool | true, false | Round-trip | PASS |
| CyGuid | Guid.Empty, NewGuid | Round-trip | PASS |
| CyString | Empty | Round-trip | PASS |
| CyString | Single char "A" | Round-trip | PASS |
| CyString | 100,000 chars | Round-trip | PASS |
| CyString | Unicode (emoji, CJK, Arabic) | Round-trip | PASS |
| CyString | Embedded \0 characters | Round-trip | PASS |
| CyBytes | Empty array (0 bytes) | Round-trip | PASS |
| CyBytes | Single byte [0x42] | Round-trip | PASS |
| CyBytes | 16 MB (exact limit) | Round-trip | PASS |
| CyBytes | All zeros (1024 bytes) | Round-trip | PASS |
| CyBytes | All 0xFF (1024 bytes) | Round-trip | PASS |
| CyDateTime | DateTime.MinValue | Round-trip | PASS |
| CyDateTime | DateTime.MaxValue | Round-trip | PASS |
| CyDateTime | Unix epoch | Round-trip | PASS |
| CyDateTime | UtcNow | Round-trip | PASS |
| AutoDestroy | 10/10 decryptions (at threshold) | Disposed | PASS |
| AutoDestroy | 9/10 decryptions (before threshold) | NOT disposed | PASS |
| AutoDestroy | 50 threads racing threshold (10) | <=10 succeed | PASS |
| RateLimit | At limit (100 calls) | No exception | PASS |
| RateLimit | Burst, wait 1.1s, burst | Second burst OK | PASS |
| RateLimit | Rapid exceed | RateLimitExceededException | PASS |

**Key Finding**: All boundary values round-trip correctly, including IEEE 754 special values (NaN, Infinity). AutoDestroy fires exactly at the threshold. Rate limiter sliding window works correctly.

---

## 5. Resilience Results

**12 tests, all passed**

| Test | Corruption Type | Expected Exception | Result |
|------|-----------------|--------------------|--------|
| AES-GCM — Flipped bit | Single bit flip in ciphertext | CryptographicException | PASS |
| AES-GCM — Truncated | Remove last byte | CryptographicException | PASS |
| AES-GCM — Wrong key | Different 256-bit key | CryptographicException | PASS |
| AES-GCM — Corruption under load | 20 threads, corrupted data | CryptographicException | PASS |
| Envelope — Tampered HMAC | Modified HMAC-SHA512 | SecurityException | PASS |
| Envelope — Wrong version | Version byte 0xFF | ArgumentException | PASS |
| Envelope — Truncated | Below MinEnvelopeLength | Exception | PASS |
| Stream — Missing final chunk | No isFinal marker | Detected | PASS |
| Stream — Reordered chunks | Swapped sequence numbers | CryptographicException | PASS |
| KeyManager — TTL expiry | 1s TTL, access after 1.1s | KeyExpiredException | PASS |
| KeyManager — Rotate before expiry | Rotation resets TTL | No exception | PASS |
| FHE — No engine registered | HomomorphicBasic without SEAL | InvalidOperationException | PASS |

**Key Finding**: All cryptographic integrity checks work correctly. AES-GCM authentication tags detect any bit modification. HMAC envelope verification rejects tampered data. Chunked stream encryption detects reordering and truncation.

---

## 6. Integration Results

**12 tests (9 passed, 3 skipped FHE/pipe)**

| Test | Entities/Connections | Throughput | Result |
|------|---------------------|-----------|--------|
| JSON — Bulk serialize/deserialize (10 types) | 1000 objects | 1,039 ops/s/type | PASS |
| JSON — Concurrent round-trip | 20 threads x 100 | No corruption | PASS |
| EF Core — Bulk insert + read-back | 100 entities | 56 ops/s | PASS |
| EF Core — Concurrent insert/read | 200 entities | No corruption | PASS |
| ChunkedEngine — 1000-chunk pipeline | 1000 chunks | 465 ops/s | PASS |
| CyFileStream — Multi-block pipeline | 50 blocks x 4KB | 200 KB total | PASS |
| Network — 10 concurrent clients | 10 connections | All succeed | PASS |
| Network — Client disconnect recovery | 1 disconnect | Server recovers | PASS |
| Named Pipes (Windows only) | - | - | SKIP (Linux) |
| Mixed FHE + Standard | - | - | SKIP (no SEAL) |

**Key Finding**: JSON serialization, EF Core persistence, and network streaming all work correctly under concurrent load. The `CyNetworkServer` recovers cleanly from client disconnections.

---

## Recommendations

1. **CyList/CyDictionary thread safety**: These collections are not thread-safe. Users must provide external synchronization for concurrent access. Consider documenting this prominently or providing `ConcurrentCyList<T>` / `ConcurrentCyDictionary<K,V>` wrappers.

2. **CyDictionary.Dispose() null reference**: Under concurrent access, the internal dictionary can enter a corrupted state where `Dispose()` encounters null entries. Consider adding a null guard in the dispose loop.

3. **Pinned array fragmentation**: `SecureBuffer` uses `GC.AllocateArray(pinned: true)` which causes heap fragmentation under rapid allocation/deallocation patterns. The `SecureBufferPool` mitigates this effectively — recommend pool usage in high-throughput scenarios.

4. **FHE engine dependency**: Tests requiring SEAL (BFV/CKKS) are skipped in this environment. Full FHE stress testing requires SEAL engine registration via DI.

5. **Named pipe support**: `CyPipeStream` is Windows-specific. Consider documenting platform limitations or implementing Unix domain socket fallback.

---

## Test Project Structure

```
tests/CyTypes.StressTests/
├── Infrastructure/         (5 files: config, metrics, memory tracker, throughput counter, port allocator)
├── Concurrency/           (8 files, 21 tests)
├── MemoryPressure/        (5 files, 15 tests)
├── Throughput/            (5 files, 13 tests)
├── Boundary/              (6 files, 33 tests)
├── Resilience/            (5 files, 12 tests)
└── Integration/           (6 files, 12 tests)
Total: 40 files, 106 tests
```
