# Getting Started with CyTypes

## Installation

Install the NuGet packages for the components you need:

```bash
# Core primitives (CyInt, CyString, CyBool, etc.)
dotnet add package CyTypes.Primitives

# EF Core integration
dotnet add package CyTypes.EntityFramework

# Streaming encryption (file, IPC, network)
dotnet add package CyTypes.Streams

# Fully homomorphic encryption (Microsoft SEAL)
dotnet add package CyTypes.Fhe

# Logging and audit sinks
dotnet add package CyTypes.Logging
```

## Basic Usage

Every CyType encrypts its value in memory on construction using AES-256-GCM.
The plaintext is never stored -- only encrypted bytes in pinned secure buffers.

```csharp
using CyTypes.Primitives;
using CyTypes.Core.Policy;

// Create encrypted values (uses SecurityPolicy.Balanced by default)
using var secret = new CyInt(42);
using var name = new CyString("Alice");

// Arithmetic works directly on encrypted values
using var a = new CyInt(10);
using var b = new CyInt(20);
using var sum = a + b; // result is also encrypted

// ToString() never exposes plaintext
Console.WriteLine(secret); // [CyInt:Encrypted|Policy=Balanced|Compromised=False]
```

## Decrypting Values

Decryption is deliberately verbose to force awareness:

```csharp
int plaintext = secret.ToInsecureInt();    // marks instance as compromised
string text = name.ToInsecureString();      // marks instance as compromised
```

## Security Policies

Each CyType instance is governed by a `SecurityPolicy` that controls encryption,
memory protection, key rotation, audit logging, and taint tracking.

```csharp
// Use a predefined policy
using var high = new CyInt(42, SecurityPolicy.Maximum);
using var fast = new CyInt(42, SecurityPolicy.Performance);

// Or build a custom policy
var custom = new SecurityPolicyBuilder()
    .WithName("MyPolicy")
    .WithMemoryProtection(MemoryProtection.PinnedLockedReEncrypting)
    .WithTaintMode(TaintMode.Strict)
    .WithMaxDecryptionCount(5)
    .WithKeyRotation(KeyRotationPolicy.EveryNOperations(500))
    .Build();

using var val = new CyInt(42, custom);
```

## Dispose Pattern

All CyTypes implement `IDisposable`. Disposal zeros secure buffers and keys.
Always use `using` or call `Dispose()` explicitly.

```csharp
using var ssn = new CyString("123-45-6789", SecurityPolicy.Maximum);
// ... use ssn ...
// Disposal zeros all encrypted buffers and key material
```

Failure to dispose means the finalizer will clean up, but deterministic
disposal is strongly recommended to minimize the window of exposure.

## Available Types

| CyType       | Wraps          | Decryption Method       |
|--------------|----------------|-------------------------|
| `CyInt`      | `int`          | `ToInsecureInt()`       |
| `CyLong`     | `long`         | `ToInsecureLong()`      |
| `CyFloat`    | `float`        | `ToInsecureFloat()`     |
| `CyDouble`   | `double`       | `ToInsecureDouble()`    |
| `CyDecimal`  | `decimal`      | `ToInsecureDecimal()`   |
| `CyBool`     | `bool`         | `ToInsecureBool()`      |
| `CyString`   | `string`       | `ToInsecureString()`    |
| `CyGuid`     | `Guid`         | `ToInsecureGuid()`      |
| `CyDateTime` | `DateTime`     | `ToInsecureDateTime()`  |
| `CyBytes`    | `byte[]`       | `ToInsecureBytes()`     |

All types support implicit conversion from their native type,
operator overloads, `IFormattable`, `IEquatable<T>`, and `IComparable<T>`.

## Encrypted Collections

`CyList<T>` and `CyDictionary<TKey, TValue>` hold encrypted elements and automatically
dispose them on removal. See [collections-guide.md](collections-guide.md).

```csharp
using CyTypes.Collections;

using var list = new CyList<CyInt>();
list.Add(new CyInt(10));
list.Add(new CyInt(20));
// Elements disposed automatically when list is disposed
```

## Fully Homomorphic Encryption (FHE)

Compute on encrypted data without decrypting. BFV for integers, CKKS for floating-point.
See [fhe-guide.md](fhe-guide.md).

```csharp
using var a = new CyInt(10, SecurityPolicy.HomomorphicBasic);
using var b = new CyInt(20, SecurityPolicy.HomomorphicBasic);
using var sum = a + b; // computed on ciphertext, never decrypted
```

## Post-Quantum Key Exchange

Hybrid ECDH P-256 + ML-KEM-1024 key exchange for quantum-resistant sessions.
See [pqc-guide.md](pqc-guide.md).

## Encrypted Streaming

File, IPC, and TCP streaming with chunked AES-256-GCM and automatic key exchange.
See [streaming-guide.md](streaming-guide.md).

## Roslyn Analyzer

Compile-time security checks (CY0001--CY0005) catch common mistakes like
forgetting to dispose CyTypes or calling `ToInsecure*()` outside marked contexts.
See [analyzer-guide.md](analyzer-guide.md).

## Next Steps

| Guide                                        | Topic                              |
|----------------------------------------------|------------------------------------|
| [policy-reference.md](policy-reference.md)   | SecurityPolicy and builder API     |
| [fhe-guide.md](fhe-guide.md)                 | FHE (BFV + CKKS)                  |
| [pqc-guide.md](pqc-guide.md)                 | Post-quantum key exchange          |
| [collections-guide.md](collections-guide.md) | Encrypted collections              |
| [streaming-guide.md](streaming-guide.md)     | Encrypted file/IPC/TCP streams     |
| [ef-core-guide.md](ef-core-guide.md)         | Entity Framework Core integration  |
| [analyzer-guide.md](analyzer-guide.md)       | Roslyn analyzer diagnostics        |
| [migration-guide.md](migration-guide.md)     | Migrating from standard .NET types |
| [security-model.md](security-model.md)       | Security model and guarantees      |
