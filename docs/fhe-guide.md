# Fully Homomorphic Encryption (FHE) Guide

## Overview

CyTypes supports fully homomorphic encryption via Microsoft SEAL through the `CyTypes.Fhe` package. Two schemes are available:

- **BFV** -- exact integer arithmetic on encrypted data (`CyInt`, `CyLong`)
- **CKKS** -- approximate floating-point arithmetic on encrypted data (`CyFloat`, `CyDouble`, `CyDecimal`)

FHE enables computation directly on ciphertexts without ever decrypting them.

## When to Use FHE

- Computing on data you cannot or should not decrypt (e.g., multi-party computation)
- Aggregation in untrusted environments
- Scenarios where even the computing party should not see plaintext

## Installation

```bash
dotnet add package CyTypes.Fhe
```

## BFV -- Integer Arithmetic

### Setup

Initialize the SEAL BFV engine and register it before creating CyType instances:

```csharp
using CyTypes.Fhe.KeyManagement;
using CyTypes.Fhe.Crypto;
using CyTypes.Primitives.Shared;
using CyTypes.Core.Policy;

var keyManager = new SealKeyManager();
keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());

var engine = new SealBfvEngine(keyManager);
FheEngineProvider.Configure(engine);
```

### Supported Operations

With `SecurityPolicy.HomomorphicBasic`, integer types (`CyInt`, `CyLong`) support:

| Operation  | Operator | Method on `IFheEngine` |
|------------|----------|------------------------|
| Add        | `+`      | `Add(a, b)`            |
| Subtract   | `-`      | `Subtract(a, b)`       |
| Multiply   | `*`      | `Multiply(a, b)`       |
| Negate     | `-`      | `Negate(a)`            |

```csharp
using var a = new CyInt(10, SecurityPolicy.HomomorphicBasic);
using var b = new CyInt(20, SecurityPolicy.HomomorphicBasic);

// These operations happen entirely on ciphertext -- no decryption
using var sum = a + b;
using var product = a * b;

// Only decrypt when you need the result
int result = sum.ToInsecureInt(); // 30
```

## CKKS -- Floating-Point Arithmetic

### Setup

```csharp
var ckksKeyManager = new SealKeyManager();
ckksKeyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());

var ckksEngine = new SealCkksEngine(ckksKeyManager);
FheEngineProvider.Configure(ckksEngine);
```

### Supported Operations

With `SecurityPolicy.HomomorphicBasic`, floating-point types (`CyFloat`, `CyDouble`, `CyDecimal`) support:

| Operation  | Operator | Method on `IFheFloatingPointEngine` |
|------------|----------|-------------------------------------|
| Add        | `+`      | `Add(a, b)`                        |
| Subtract   | `-`      | `Subtract(a, b)`                   |
| Multiply   | `*`      | `Multiply(a, b)` (auto-rescale)    |
| Negate     | `-`      | `Negate(a)`                        |

```csharp
using var a = new CyDouble(3.14159, SecurityPolicy.HomomorphicBasic);
using var b = new CyDouble(2.71828, SecurityPolicy.HomomorphicBasic);

using var sum = a + b;
double result = sum.ToInsecureDouble(); // ~5.85987
```

> **Precision note:** CKKS provides approximately 15 significant digits of precision. `CyDecimal`'s 28-29 digit precision is NOT preserved through FHE operations.

## Homomorphic Comparisons

`ComparisonMode.HomomorphicCircuit` enables encrypted comparisons on integers via encrypted difference with deferred sign extraction.

### Setup

Both BFV and CKKS engines must be registered, plus the comparison engine:

```csharp
// BFV engine (for integer FHE)
var bfvKm = new SealKeyManager();
bfvKm.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
var bfvEngine = new SealBfvEngine(bfvKm);
FheEngineProvider.Configure(bfvEngine);

// CKKS engine (used internally by comparison)
var ckksKm = new SealKeyManager();
ckksKm.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
var ckksEngine = new SealCkksEngine(ckksKm);
FheEngineProvider.Configure(ckksEngine);

// Comparison engine
FheEngineProvider.Configure(new SealComparisonEngine(bfvEngine, ckksEngine));
```

### Usage

```csharp
var policy = new SecurityPolicyBuilder()
    .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
    .WithComparisonMode(ComparisonMode.HomomorphicCircuit)
    .WithMemoryProtection(MemoryProtection.PinnedLocked)
    .Build();

using var x = new CyInt(42, policy);
using var y = new CyInt(17, policy);

bool greater = x > y;  // True -- computed on encrypted data
bool equal = x == y;    // False
```

## Encrypted String Equality

> **Naming clarification:** Despite the name `HomomorphicEquality`, this mode does **not** use FHE. It uses **AES-SIV (RFC 5297) deterministic encryption** — same plaintext always produces the same ciphertext, enabling equality comparison on ciphertexts without decryption. The name reflects its position in the `HomomorphicFull` policy preset alongside genuine FHE operations, not the underlying cryptographic mechanism.

### Setup

```csharp
using var sivEngine = AesSivEngine.CreateWithRandomKey();
FheEngineProvider.Configure(sivEngine);
```

### Usage

```csharp
var policy = new SecurityPolicyBuilder()
    .WithStringOperationMode(StringOperationMode.HomomorphicEquality)
    .WithMemoryProtection(MemoryProtection.PinnedLocked)
    .Build();

using var s1 = new CyString("secret", policy);
using var s2 = new CyString("secret", policy);
using var s3 = new CyString("other", policy);

bool eq = s1 == s2;  // True
bool ne = s1 == s3;  // False
```

### Security Trade-offs

AES-SIV deterministic encryption provides IND-CPA security but **not** IND-CCA2. This has concrete implications:

- **Equality pattern leakage**: An attacker with memory access who observes multiple ciphertexts can determine which values are equal without knowing the plaintext. This enables **frequency analysis** — if the attacker knows the distribution of possible values (e.g., a set of known usernames), they can correlate ciphertext frequencies to likely plaintexts.
- **No ordering**: Deterministic ciphertexts do not preserve ordering — only equality is supported.
- **Constant-time comparison**: Ciphertext comparison uses fixed-time operations to prevent timing side-channels.

**When to use:** Equality checks on encrypted strings where the set of possible values is large or unpredictable (e.g., session tokens, random identifiers). **Avoid** when the plaintext domain is small or the frequency distribution is skewed (e.g., boolean flags, enum labels) — in those cases, frequency analysis trivially reveals the mapping.

## Parameter Presets

`SealParameterPresets` provides presets for both schemes:

| Preset            | Scheme | Poly Modulus Degree | Security Level | Multiplications |
|-------------------|--------|---------------------|----------------|-----------------|
| `Bfv128Bit()`     | BFV    | 4096                | 128-bit        | ~2-3            |
| `Bfv192Bit()`     | BFV    | 8192                | 192-bit        | ~5-6            |
| `Ckks128Bit()`    | CKKS   | 8192                | 128-bit        | ~2              |
| `Ckks192Bit()`    | CKKS   | 16384               | 192-bit        | ~5              |

Higher security levels support more operations before noise exhaustion but have larger ciphertexts and slower computation.

## Noise Budget

Every FHE ciphertext carries a noise budget that decreases with each operation. When the budget reaches zero, decryption produces incorrect results.

- **Addition** consumes minimal noise
- **Multiplication** consumes significant noise (relinearization is applied automatically)
- Check remaining budget: `engine.GetNoiseBudget(ciphertextBytes)`
- Track budgets: use `NoiseBudgetTracker` to monitor and alert before exhaustion

```csharp
var tracker = new NoiseBudgetTracker(engine, minimumBudget: 10);
// tracker throws NoiseBudgetExhaustedException if budget drops below threshold
```

## Policy Configuration

FHE requires specific policy settings:

```csharp
// Predefined policies
using var val = new CyInt(42, SecurityPolicy.HomomorphicBasic);  // add/sub/mul
using var val2 = new CyInt(42, SecurityPolicy.HomomorphicFull);  // + comparisons + string equality

// Or build a custom FHE-enabled policy
var policy = new SecurityPolicyBuilder()
    .WithName("CustomFHE")
    .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
    .WithComparisonMode(ComparisonMode.HomomorphicCircuit)        // optional
    .WithStringOperationMode(StringOperationMode.HomomorphicEquality) // optional
    .WithMemoryProtection(MemoryProtection.PinnedLocked) // required minimum
    .WithTaintMode(TaintMode.Standard)
    .Build();
```

Builder validation enforces:
- `HomomorphicBasic` or `HomomorphicFull` arithmetic requires at least `PinnedLocked` memory
- `HomomorphicFull` requires `AuditLevel.AllOperations`

## Key Management

`SealKeyManager` manages the SEAL context, public key, secret key, relinearization keys, and Galois keys (CKKS):

```csharp
var keyManager = new SealKeyManager();
keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());

// Export keys for storage/transport
using var bundle = keyManager.ExportKeyBundle();
// bundle.PublicKey, bundle.SecretKey, bundle.RelinKeys, bundle.GaloisKeys
```

The `SealCiphertextSerializer` handles serialization and deserialization of SEAL ciphertexts for storage or transport.

## Cleanup

Always reset the global provider when done:

```csharp
FheEngineProvider.Reset();
```

## Limitations

- **No key rotation** -- `RotateKeyAndReEncrypt()` throws `NotSupportedException` for FHE values
- **Ciphertext size** -- a single encrypted value is thousands of bytes (vs. ~60 bytes for AES-GCM)
- **Performance** -- FHE operations are orders of magnitude slower than AES-based SecureEnclave operations
- **Noise accumulation** -- deep computation chains (many multiplications) exhaust the noise budget
- **CKKS precision** -- approximate scheme; ~15 significant digits, not suitable for exact decimal arithmetic
