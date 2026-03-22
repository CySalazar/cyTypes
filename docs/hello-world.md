# Hello World — CyTypes in 5 Minutes

This guide covers the absolute minimum to start using CyTypes: create encrypted values, operate on them, and dispose safely. No FHE, no PQC, no policy configuration — just encrypted-by-default primitives.

## Install

```bash
dotnet add package CyTypes.Primitives
```

## Create, Compute, Decrypt

```csharp
using CyTypes.Primitives;

// Values are AES-256-GCM encrypted in memory on construction
using var a = new CyInt(10);
using var b = new CyInt(20);

// Arithmetic works directly on encrypted values
using var sum = a + b;

// ToString() never exposes plaintext
Console.WriteLine(sum); // [CyInt:Encrypted|Policy=Balanced|Compromised=False]

// Explicit decryption — deliberately verbose
int result = sum.ToInsecureInt(); // 30
Console.WriteLine(result);
```

## Strings

```csharp
using var name = new CyString("Alice");
using var greeting = new CyString("Hello, ");

// Concatenation returns an encrypted result
using var message = greeting + name;

Console.WriteLine(message); // [CyString:Encrypted|Policy=Balanced|Compromised=False]
string plain = message.ToInsecureString(); // "Hello, Alice"
```

## Why `using`?

Every CyType holds encrypted buffers and key material. `Dispose()` zeros them cryptographically. Always use `using` statements or call `Dispose()` explicitly:

```csharp
// Good — deterministic cleanup
using var ssn = new CyString("123-45-6789");

// Also good — explicit dispose
var temp = new CyInt(99);
try { /* ... */ }
finally { temp.Dispose(); }
```

## What's Next?

| Step | Guide | What you'll learn |
|------|-------|-------------------|
| 1 | [Getting Started](getting-started.md) | Security policies, all 10 types, collections |
| 2 | [Migration Guide](migration-guide.md) | Replace `int`/`string` with `CyInt`/`CyString` in existing code |
| 3 | [FHE Guide](fhe-guide.md) | Compute on encrypted data without decrypting |
| 4 | [Streaming Guide](streaming-guide.md) | Encrypted file, IPC, and TCP streams |

Or run the sample projects:

```bash
# Console walkthrough — covers all features end-to-end
dotnet run --project examples/CyTypes.Sample.Console

# ASP.NET Core WebAPI — DI, EF Core, encrypted entities
dotnet run --project examples/CyTypes.Sample.WebApi

# Interactive demo menu — 21 scenarios
dotnet run --project examples/CyTypes.Examples
```
