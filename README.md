# cyTypes

**Always-encrypted primitive types for .NET** — AES-256-GCM encryption, taint tracking, security policies, and memory protection built into every value.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET 9.0](https://img.shields.io/badge/.NET-9.0-purple.svg)](https://dotnet.microsoft.com/)
[![Build](https://github.com/cySalazar/cyTypes/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/cySalazar/cyTypes/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cySalazar/cyTypes/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/cySalazar/cyTypes/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cySalazar/cyTypes/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cySalazar/cyTypes)
[![NuGet](https://img.shields.io/nuget/v/CyTypes.svg)](https://www.nuget.org/packages/CyTypes)

> Copyright 2026 Matteo Sala (cysalazar@cysalazar.com)

---

## Table of Contents

- [Overview](#overview)
- [Why cyTypes?](#why-cytypes)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [.NET Native vs cyTypes — Side-by-Side Comparison](#net-native-vs-cytypes--side-by-side-comparison)
  - [Integers](#integers-int-vs-cyint)
  - [Strings](#strings-string-vs-cystring)
  - [Booleans](#booleans-bool-vs-cybool)
  - [Floating-Point](#floating-point-doublefloat-vs-cydoublecyfloat)
  - [Decimal](#decimal-decimal-vs-cydecimal)
  - [Byte Arrays, Guid, DateTime](#byte-arrays-guid-datetime)
  - [Collections](#collections-list-vs-cylist-dictionary-vs-cydictionary)
  - [EF Core Integration](#ef-core-with-and-without-cytypes)
  - [JSON Serialization](#json-serialization)
  - [Logging with Auto-Redaction](#logging-with-auto-redaction)
  - [Encrypted Streams (File, IPC, TCP)](#encrypted-streams-file-ipc-tcp)
  - [Dependency Injection](#dependency-injection-setup)
- [Supported Types](#supported-types)
- [API Reference](#api-reference)
  - [CyInt / CyLong](#cyint--cylong)
  - [CyFloat / CyDouble](#cyfloat--cydouble)
  - [CyDecimal](#cydecimal)
  - [CyBool](#cybool)
  - [CyString](#cystring)
  - [CyBytes](#cybytes)
  - [CyGuid](#cyguid)
  - [CyDateTime](#cydatetime)
- [CyTypeBase — Common Functionality](#cytypebase--common-functionality)
- [Security Policies](#security-policies)
- [Taint Tracking](#taint-tracking)
- [Auto-Destroy](#auto-destroy)
- [Key Rotation](#key-rotation)
- [Memory Protection](#memory-protection)
- [Roslyn Analyzer (CY0001-CY0004)](#roslyn-analyzer-cy0001-cy0004)
- [FHE — Fully Homomorphic Encryption](#fhe--fully-homomorphic-encryption)
- [Benchmarks](#benchmarks)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Project Structure](#project-structure)
- [Building & Testing](#building--testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

cyTypes replaces standard .NET primitives (`int`, `string`, `bool`, etc.) with encrypted counterparts (`CyInt`, `CyString`, `CyBool`, etc.) that keep data encrypted in memory at all times using AES-256-GCM in pinned, locked buffers.

**Key features:**
- **Always-encrypted**: Values are encrypted at rest in memory; plaintext exists only transiently during operations and is zeroed promptly
- **Taint tracking**: Automatic propagation of compromise/taint state through operations
- **Security policies**: Configurable security levels (Maximum, Balanced, Performance, HomomorphicBasic)
- **Memory protection**: Pinned buffers + OS-level memory locking (mlock/VirtualLock) + zeroing on dispose
- **Auto-destroy**: Automatic disposal after configurable decryption count threshold
- **Drop-in operators**: Standard arithmetic, comparison, and conversion operators

## Why cyTypes?

1. **Sensitive data in .NET lives as plaintext in memory.** A memory dump, a debugger attach, or a GC heap inspection exposes every `int salary`, `string ssn`, and `decimal balance` in your process. `SecureString` is deprecated and never covered numeric types.

2. **cyTypes is a drop-in replacement.** Change `int` to `CyInt`, `string` to `CyString` — your existing operators, comparisons, and LINQ queries keep working. No API redesign required.

3. **Security is automatic, not opt-in.** Taint tracking, auto-destroy, and memory zeroing happen without developer intervention. The Roslyn analyzer catches mistakes at compile time.

## Installation

```bash
# Core primitives (CyInt, CyString, CyBool, CyBytes, etc.)
dotnet add package CyTypes.Primitives

# Core crypto engine (included as dependency of Primitives)
dotnet add package CyTypes.Core

# Encrypted collections (CyList, CyDictionary)
dotnet add package CyTypes.Collections

# Roslyn analyzer — compile-time security checks
dotnet add package CyTypes.Analyzer

# Auto-redacting logger
dotnet add package CyTypes.Logging

# Entity Framework Core value converters
dotnet add package CyTypes.EntityFramework

# ASP.NET Core dependency injection
dotnet add package CyTypes.DependencyInjection

# Fully Homomorphic Encryption (Microsoft SEAL)
dotnet add package CyTypes.Fhe

# Encrypted streaming (file, IPC, TCP)
dotnet add package CyTypes.Streams
```

## Quick Start

```csharp
using CyTypes.Primitives;

// Implicit conversion — encrypts immediately
CyInt balance = 1000;

// Arithmetic stays encrypted
using var deposit = new CyInt(250);
using var newBalance = balance + deposit;

// Explicit decryption — marks instance as compromised
int plaintext = newBalance.ToInsecureInt();
Console.WriteLine(plaintext); // 1250
Console.WriteLine(newBalance.IsCompromised); // True
```

## Documentation

| Guide | Description |
|-------|-------------|
| **[Hello World](docs/hello-world.md)** | **Start here** — 5-minute minimal introduction |
| [Getting Started](docs/getting-started.md) | Full feature overview: policies, all 10 types, collections |
| [Migration Guide](docs/migration-guide.md) | Replace `int`/`string` with `CyInt`/`CyString` in existing code |
| [Security Model](docs/security-model.md) | Threat model, guarantees, and known limitations |
| [Policy Reference](docs/policy-reference.md) | SecurityPolicy and builder API |
| [FHE Guide](docs/fhe-guide.md) | Fully Homomorphic Encryption (BFV + CKKS) |
| [PQC Guide](docs/pqc-guide.md) | Post-quantum hybrid key exchange (ECDH P-256 + ML-KEM-1024) |
| [Streaming Guide](docs/streaming-guide.md) | Encrypted file, IPC, and TCP streams |
| [Collections Guide](docs/collections-guide.md) | CyList, CyDictionary |
| [EF Core Guide](docs/ef-core-guide.md) | Entity Framework Core integration |
| [DI + FHE Guide](docs/di-fhe-guide.md) | Dependency injection with FHE engines |
| [Analyzer Guide](docs/analyzer-guide.md) | Roslyn analyzer diagnostics (CY0001–CY0004) |

## Sample Projects

```bash
# Console walkthrough — covers all features end-to-end
dotnet run --project examples/CyTypes.Sample.Console

# ASP.NET Core WebAPI — DI, EF Core, encrypted entities
dotnet run --project examples/CyTypes.Sample.WebApi

# Interactive demo menu — 22 scenarios from basics to FHE + memory forensics
dotnet run --project examples/CyTypes.Examples
```

---

## .NET Native vs cyTypes — Side-by-Side Comparison

### Integers: `int` vs `CyInt`

```csharp
// ── .NET native ──────────────────────────────────
int a = 100;
int b = 50;
int sum = a + b;              // 150 — plaintext in memory
int product = a * b;          // 5000
bool equal = (a == b);        // false
string s = a.ToString();      // "100"
int parsed = int.Parse("42"); // 42

// ── cyTypes ──────────────────────────────────────
CyInt ca = 100;               // implicit conversion, encrypted immediately
using var cb = new CyInt(50);
using var cSum = ca + cb;     // encrypted arithmetic
using var cProd = ca * cb;    // encrypted multiplication
bool cEqual = (ca == cb);     // constant-time encrypted comparison
CyInt cParsed = CyInt.Parse("42");

// Decryption is explicit and tracked
int plainSum = cSum.ToInsecureInt();   // 150 — cSum.IsCompromised = true
int plainProd = cProd.ToInsecureInt(); // 5000

// Bitwise operators work too
using var and = ca & cb;      // bitwise AND
using var or  = ca | cb;      // bitwise OR
using var xor = ca ^ cb;     // bitwise XOR
using var not = ~ca;          // bitwise NOT
using var shl = ca << 2;     // shift left
using var shr = ca >> 1;     // shift right

// Overflow detection (with Maximum policy)
using var safe = new CyInt(int.MaxValue, SecurityPolicy.Maximum);
// safe + new CyInt(1) → throws OverflowException
```

### Strings: `string` vs `CyString`

```csharp
// ── .NET native ──────────────────────────────────
string greeting = "Hello, World!";
int len = greeting.Length;                // 13
string upper = greeting.ToUpper();       // "HELLO, WORLD!"
string sub = greeting.Substring(0, 5);   // "Hello"
bool contains = greeting.Contains("World"); // true
string[] parts = greeting.Split(',');    // ["Hello", " World!"]
string joined = string.Join("-", parts); // "Hello- World!"

// ── cyTypes ──────────────────────────────────────
using var cGreeting = new CyString("Hello, World!");
int cLen = cGreeting.Length;                       // 13 — metadata, no decryption
using var cUpper = cGreeting.ToUpper();            // encrypted result
using var cSub = cGreeting.Substring(0, 5);        // encrypted result
bool cContains = cGreeting.Contains("World");      // true — no compromise flag

CyString[] cParts = cGreeting.Split(',');          // encrypted array
using var cJoined = CyString.Join("-", cParts);    // encrypted join

// Secure comparison — constant-time, no compromise
bool eq = cGreeting.SecureEquals(new CyString("Hello, World!")); // true

// Indexer — returns plaintext char, marks compromise
char c = cGreeting[0]; // 'H', cGreeting.IsCompromised = true

// Additional query methods — no compromise
bool starts = cGreeting.StartsWith("Hello");       // true
bool ends = cGreeting.EndsWith("!");               // true
int idx = cGreeting.IndexOf("World");              // 7

// Transformation methods — all return new encrypted CyString
using var trimmed = cGreeting.Trim();
using var replaced = cGreeting.Replace("World", ".NET");
using var padded = cGreeting.PadRight(20, '.');
using var inserted = cGreeting.Insert(5, "!!");
```

### Booleans: `bool` vs `CyBool`

```csharp
// ── .NET native ──────────────────────────────────
bool x = true;
bool y = false;
bool andResult = x & y;   // false
bool orResult  = x | y;   // true
bool xorResult = x ^ y;   // true
bool notResult = !x;      // false

// ── cyTypes ──────────────────────────────────────
CyBool cx = true;             // implicit conversion
using var cy = new CyBool(false);
using var cAnd = cx & cy;     // encrypted AND
using var cOr  = cx | cy;     // encrypted OR
using var cXor = cx ^ cy;     // encrypted XOR
using var cNot = !cx;         // encrypted NOT

bool plain = cAnd.ToInsecureBool(); // false — cAnd.IsCompromised = true
```

### Floating-Point: `double`/`float` vs `CyDouble`/`CyFloat`

```csharp
// ── .NET native ──────────────────────────────────
double d = 3.14159;
double nan = double.NaN;
double inf = double.PositiveInfinity;
bool isNan = double.IsNaN(nan); // true

// ── cyTypes ──────────────────────────────────────
CyDouble cd = 3.14159;                         // implicit conversion
using var cNan = CyDouble.NaN;                 // encrypted NaN
using var cInf = CyDouble.PositiveInfinity;    // encrypted Infinity
using var cEps = CyDouble.Epsilon;             // encrypted Epsilon

// Arithmetic
using var result = cd + new CyDouble(1.0);     // encrypted addition
using var div = cd / new CyDouble(2.0);        // encrypted division

// CyFloat — same API
CyFloat cf = 2.71828f;
using var cfNan = CyFloat.NaN;
using var cfInf = CyFloat.PositiveInfinity;
using var cfEps = CyFloat.Epsilon;

// Parse
CyDouble parsed = CyDouble.Parse("3.14");
bool ok = CyFloat.TryParse("2.71", out CyFloat? fParsed);
```

### Decimal: `decimal` vs `CyDecimal`

```csharp
// ── .NET native ──────────────────────────────────
decimal price = 29.99m;
decimal tax = price * 0.21m;
decimal total = price + tax;

// ── cyTypes — ideal for financial calculations ──
using var cPrice = new CyDecimal(29.99m);
using var cTaxRate = new CyDecimal(0.21m);
using var cTax = cPrice * cTaxRate;            // encrypted, never plaintext
using var cTotal = cPrice + cTax;

// Predefined constants
using var zero = CyDecimal.Zero;               // 0m
using var one  = CyDecimal.One;                // 1m
using var neg  = CyDecimal.MinusOne;           // -1m

decimal plainTotal = cTotal.ToInsecureDecimal(); // 36.2879m
```

### Byte Arrays, Guid, DateTime

```csharp
// ── CyBytes ──────────────────────────────────────
byte[] raw = new byte[] { 0x01, 0x02, 0x03 };
using var cBytes = new CyBytes(raw);
int byteLen = cBytes.Length;                   // 3 — metadata
byte[] decrypted = cBytes.ToInsecureBytes();   // marks compromised

// Implicit/explicit conversions
CyBytes fromArr = (CyBytes)raw;               // implicit
byte[] toArr = (byte[])fromArr;                // explicit — compromises

// ── CyGuid ───────────────────────────────────────
Guid id = Guid.NewGuid();
CyGuid cId = id;                               // implicit conversion
Guid plainId = (Guid)cId;                      // explicit — compromises
bool same = (cId == new CyGuid(id));           // encrypted comparison

// ── CyDateTime ───────────────────────────────────
CyDateTime cNow = DateTime.UtcNow;             // implicit conversion
DateTime plainNow = cNow.ToInsecureDateTime(); // explicit decryption
bool before = (cNow < new CyDateTime(DateTime.MaxValue)); // comparison
```

### Collections: `List` vs `CyList`, `Dictionary` vs `CyDictionary`

```csharp
// ── .NET native ──────────────────────────────────
var list = new List<int> { 1, 2, 3 };
list.Add(4);
int first = list[0];

var dict = new Dictionary<string, int> { ["key"] = 42 };
int val = dict["key"];

// ── cyTypes (thread-safe, auto-dispose) ──────────
using var cList = new CyList<CyInt>();
cList.Add(new CyInt(1));
cList.Add(new CyInt(2));
cList.Add(new CyInt(3));
CyInt cFirst = cList[0];                       // encrypted value
int count = cList.Count;                        // 3
cList.RemoveAt(0);                              // disposes the removed element

using var cDict = new CyDictionary<string, CyString>();
cDict.Add("name", new CyString("Alice"));
cDict.Add("ssn",  new CyString("123-45-6789"));
CyString name = cDict["name"];                 // encrypted lookup
bool hasKey = cDict.ContainsKey("ssn");        // true
cDict.Remove("ssn");                            // disposes the CyString value

// Enumeration
foreach (var item in cList)
{
    // item is CyInt — still encrypted
}

// Clear disposes all elements
cList.Clear();
cDict.Clear();
```

### EF Core With and Without cyTypes

```csharp
// ── Without cyTypes — plaintext in memory ────────
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }         // plaintext
    public string SocialSecurity { get; set; } // plaintext!
    public decimal Salary { get; set; }       // plaintext!
}

// ── With cyTypes — encrypted in memory ───────────
public class SecureUser
{
    public int Id { get; set; }
    public CyString Name { get; set; }             // encrypted
    public CyString SocialSecurity { get; set; }   // encrypted
    public CyDecimal Salary { get; set; }           // encrypted
}

// DbContext configuration — one line
protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
{
    configurationBuilder.UseCyTypes(); // registers all 10 value converters
}
```

Value converters handle transparent encryption/decryption at the persistence boundary. Data is stored as native types in the database and re-encrypted on read.

Available converters: `CyIntValueConverter`, `CyLongValueConverter`, `CyFloatValueConverter`, `CyDoubleValueConverter`, `CyDecimalValueConverter`, `CyBoolValueConverter`, `CyStringValueConverter`, `CyGuidValueConverter`, `CyDateTimeValueConverter`, `CyBytesValueConverter`.

### JSON Serialization

```csharp
using CyTypes.Primitives.Serialization;
using System.Text.Json;

// Configure once
var options = new JsonSerializerOptions().AddCyTypesConverters();

// Serialize — calls ToInsecureValue() internally (marks compromised)
using var salary = new CyDecimal(85000m);
string json = JsonSerializer.Serialize(salary, options);  // "85000"

// Deserialize — creates fresh encrypted instance
CyDecimal restored = JsonSerializer.Deserialize<CyDecimal>(json, options);
// restored is a new encrypted instance, not compromised

// Works with complex objects
var user = new { Name = new CyString("Alice"), Age = new CyInt(30) };
string userJson = JsonSerializer.Serialize(user, options);
// {"Name":"Alice","Age":30}
```

Supported converters: all 10 CyTypes (`CyInt`, `CyLong`, `CyFloat`, `CyDouble`, `CyDecimal`, `CyBool`, `CyString`, `CyBytes` as base64, `CyGuid`, `CyDateTime`).

### Logging with Auto-Redaction

```csharp
// ── Without cyTypes — sensitive data leaks to logs ──
logger.LogInformation("User salary: {Salary}", salary); // "User salary: 85000" !!

// ── With cyTypes — automatic redaction ───────────────
// CyType.ToString() never exposes plaintext:
logger.LogInformation("User salary: {Salary}", cySalary);
// Output: "User salary: [CyDecimal:Encrypted|Policy=Balanced|Compromised=False]"

// RedactingLogger adds an extra safety net:
using CyTypes.Logging;

var redactingLogger = new RedactingLogger(innerLogger);
redactingLogger.LogInformation("Data: {Data}", someString);
// Automatically redacts hex payloads, base64 payloads, and CyType metadata patterns
```

The `RedactingLoggerProvider` wraps any `ILoggerProvider` to apply redaction across your entire logging pipeline.

### Encrypted Streams (File, IPC, TCP)

```csharp
// ── .NET native — file I/O ──────────────────
byte[] data = Encoding.UTF8.GetBytes("sensitive payload");
File.WriteAllBytes("data.bin", data);               // plaintext on disk
byte[] read = File.ReadAllBytes("data.bin");         // plaintext in memory

// ── cyTypes — encrypted file I/O ────────────
using CyTypes.Streams;
using CyTypes.Streams.File;

byte[] key = RandomNumberGenerator.GetBytes(32);
using (var file = CyFileStream.CreateWrite("data.cys", key))
    file.Write(data);                                 // AES-256-GCM chunked, atomic write

using (var file = CyFileStream.OpenRead("data.cys", key))
{
    var buf = new byte[data.Length];
    file.Read(buf);                                   // decrypted + HMAC verified
}

// Passphrase-based (HKDF-derived key, salt stored in header)
using (var file = CyFileStream.CreateWrite("data.cys", "my-passphrase"))
    file.Write(data);

using (var file = CyFileStream.OpenRead("data.cys", "my-passphrase"))
{
    var buf = new byte[data.Length];
    file.Read(buf);
}
```

```csharp
// ── Typed streaming — write/read CyType values ──
using var ms = new MemoryStream();

byte[] key = RandomNumberGenerator.GetBytes(32);
using (var stream = CyStream.CreateWriter(ms, key, Guid.NewGuid()))
using (var writer = new CyStreamWriter(stream))
{
    writer.WriteValue(new CyInt(42));
    writer.WriteValue(new CyString("hello"));
    writer.Complete();   // writes footer HMAC
}

ms.Position = 0;
using (var stream = CyStream.CreateReader(ms, key))
using (var reader = new CyStreamReader(stream))
{
    foreach (var (typeId, payload) in reader.ReadAll())
    {
        // typeId = CyTypeIds.CyInt (0x0001), CyTypeIds.CyString (0x0007), etc.
    }
}
```

```csharp
// ── IPC (Named Pipes) — automatic hybrid key exchange ──
using CyTypes.Streams.Ipc;

// Server
using var server = new CyPipeServer("my-pipe");
using var conn = await server.AcceptAsync();          // ECDH + ML-KEM handshake
await conn.SendAsync(data);
byte[]? received = await conn.ReceiveAsync();

// Client
using var client = new CyPipeClient();
await client.ConnectAsync("my-pipe");                 // handshake completes automatically
await client.Stream.SendAsync(data);
byte[]? received = await client.Stream.ReceiveAsync();
```

```csharp
// ── TCP Networking — automatic hybrid key exchange ──
using CyTypes.Streams.Network;
using System.Net;

// Server
using var server = new CyNetworkServer(IPAddress.Loopback, 9000);
server.Start();
using var conn = await server.AcceptAsync();          // ECDH + ML-KEM handshake
await conn.SendAsync(data);
byte[]? received = await conn.ReceiveAsync();

// Client
using var client = new CyNetworkClient();
await client.ConnectAsync("127.0.0.1", 9000);        // handshake completes automatically
await client.Stream.SendAsync(data);
byte[]? received = await client.Stream.ReceiveAsync();
```

### Dependency Injection Setup

```csharp
using CyTypes.DependencyInjection;

// In Program.cs or Startup.cs
builder.Services.AddCyTypes(options =>
{
    options.DefaultPolicy = SecurityPolicy.Balanced;
    options.EnableRedactingLogger = true;  // default: true
    options.EnableAudit = true;            // default: true
    options.EnablePqcKeyEncapsulation = true;  // ML-KEM-1024 hybrid key exchange
});

// Optional: register FHE engine
builder.Services.AddCyTypesFhe(sp =>
{
    var keyManager = new SealKeyManager();
    // Initialize with BFV scheme parameters...
    return new SealBfvEngine(keyManager);
});

// Optional: register encrypted streaming (SessionKeyNegotiator)
builder.Services.AddCyTypesStreams();
```

`AddCyTypes` registers: default `SecurityPolicy`, crypto engine, `SecurityAuditor`, `LoggingAuditSink`, and optionally the `RedactingLoggerProvider` and PQC `MlKemKeyEncapsulation`.

---

## Supported Types

| CyType | .NET Equivalent | Operators | Interfaces |
|--------|----------------|-----------|------------|
| `CyInt` | `int` | `+  -  *  /  %  ==  !=  <  >  <=  >=  &  \|  ^  ~  <<  >>  >>>` | `IEquatable<CyInt>`, `IComparable<CyInt>` |
| `CyLong` | `long` | `+  -  *  /  %  ==  !=  <  >  <=  >=  &  \|  ^  ~  <<  >>  >>>` | `IEquatable<CyLong>`, `IComparable<CyLong>` |
| `CyDouble` | `double` | `+  -  *  /  %  ==  !=  <  >  <=  >=` | `IEquatable<CyDouble>`, `IComparable<CyDouble>` |
| `CyFloat` | `float` | `+  -  *  /  %  ==  !=  <  >  <=  >=` | `IEquatable<CyFloat>`, `IComparable<CyFloat>` |
| `CyDecimal` | `decimal` | `+  -  *  /  %  ==  !=  <  >  <=  >=` | `IEquatable<CyDecimal>`, `IComparable<CyDecimal>` |
| `CyBool` | `bool` | `&  \|  ^  !  ==  !=  <  >  <=  >=` | `IEquatable<CyBool>`, `IComparable<CyBool>` |
| `CyString` | `string` | `+  ==  !=  <  >  <=  >=  []` | `IEquatable<CyString>`, `IComparable<CyString>` |
| `CyBytes` | `byte[]` | `==  !=  <  >  <=  >=` + implicit/explicit conversions | `IEquatable<CyBytes>`, `IComparable<CyBytes>` |
| `CyGuid` | `Guid` | `==  !=  <  >  <=  >=` + implicit/explicit conversions | `IEquatable<CyGuid>`, `IComparable<CyGuid>` |
| `CyDateTime` | `DateTime` | `==  !=  <  >  <=  >=` | `IEquatable<CyDateTime>`, `IComparable<CyDateTime>` |

**Stream Type IDs** — used by `CyStreamWriter`/`CyStreamReader` for framed serialization:

| CyType | Type ID |
|--------|---------|
| `CyInt` | `0x0001` |
| `CyLong` | `0x0002` |
| `CyDouble` | `0x0003` |
| `CyFloat` | `0x0004` |
| `CyDecimal` | `0x0005` |
| `CyBool` | `0x0006` |
| `CyString` | `0x0007` |
| `CyBytes` | `0x0008` |
| `CyGuid` | `0x0009` |
| `CyDateTime` | `0x000A` |

---

## API Reference

### CyInt / CyLong

```csharp
// Construction
CyInt a = 42;                                   // implicit from int
var b = new CyInt(42);                          // explicit constructor
var c = new CyInt(42, SecurityPolicy.Maximum);  // with policy
CyInt d = CyInt.Parse("42");                    // from string
CyInt.TryParse("42", out CyInt? e);             // safe parse
CyInt.Parse("42".AsSpan());                     // from ReadOnlySpan<char>

// Constants
CyInt min = CyInt.MinValue;   // int.MinValue (-2,147,483,648)
CyInt max = CyInt.MaxValue;   // int.MaxValue (2,147,483,647)

// Decryption
int plain = a.ToInsecureInt();           // marks compromised
int cast  = (int)a;                      // explicit cast — also compromises

// Conversions (widening — no data loss)
CyLong  asLong   = a;                   // implicit CyInt → CyLong
CyDouble asDouble = a;                  // implicit CyInt → CyDouble

// Arithmetic: +, -, *, /, %
// Comparison: ==, !=, <, >, <=, >=
// Bitwise:    &, |, ^, ~, <<, >>, >>>
```

`CyLong` has the same API surface with `long` equivalents (`ToInsecureLong()`, `CyLong.MinValue`, etc.).

### CyFloat / CyDouble

```csharp
// Special IEEE 754 values
CyDouble nan      = CyDouble.NaN;
CyDouble posInf   = CyDouble.PositiveInfinity;
CyDouble negInf   = CyDouble.NegativeInfinity;
CyDouble epsilon  = CyDouble.Epsilon;
CyDouble min      = CyDouble.MinValue;
CyDouble max      = CyDouble.MaxValue;

// Same for CyFloat
CyFloat fNan    = CyFloat.NaN;
CyFloat fPosInf = CyFloat.PositiveInfinity;
CyFloat fNegInf = CyFloat.NegativeInfinity;
CyFloat fEps    = CyFloat.Epsilon;

// Parse
CyDouble d = CyDouble.Parse("3.14159");
CyFloat.TryParse("2.71", out CyFloat? f);

// Decryption
double plain = d.ToInsecureDouble();
float  fPlain = f.ToInsecureFloat();
```

### CyDecimal

```csharp
// Predefined constants — useful for financial calculations
CyDecimal zero     = CyDecimal.Zero;      // 0m
CyDecimal one      = CyDecimal.One;       // 1m
CyDecimal minusOne = CyDecimal.MinusOne;  // -1m
CyDecimal min      = CyDecimal.MinValue;
CyDecimal max      = CyDecimal.MaxValue;

// Parse
CyDecimal d = CyDecimal.Parse("29.99");
CyDecimal.TryParse("100.50", out CyDecimal? result);

// Decryption
decimal plain = d.ToInsecureDecimal();
```

### CyBool

```csharp
CyBool a = true;
using var b = new CyBool(false);

// Logical operators
using var and = a & b;     // false
using var or  = a | b;     // true
using var xor = a ^ b;     // true
using var not = !a;        // false

bool plain = a.ToInsecureBool();
```

### CyString

**Metadata** (no decryption needed):
- `Length` — string length
- `IsEmpty` — true if length is 0
- `IsNullOrEmpty(CyString?)` / `IsNullOrWhiteSpace(CyString?)` — static checks

**Transformation methods** (decrypt, compute, re-encrypt — return new `CyString`):
- `ToUpper()`, `ToLower()`, `ToUpperInvariant()`, `ToLowerInvariant()`
- `Trim()`, `TrimStart()`, `TrimEnd()`
- `Substring(startIndex)`, `Substring(startIndex, length)`
- `Replace(oldValue, newValue)`
- `Insert(startIndex, value)`
- `Remove(startIndex)`, `Remove(startIndex, count)`
- `PadLeft(totalWidth)`, `PadLeft(totalWidth, char)`, `PadRight(totalWidth)`, `PadRight(totalWidth, char)`

**Query methods** (decrypt internally but do not mark compromise):
- `Contains(value)`, `StartsWith(value)`, `EndsWith(value)`
- `IndexOf(value)`, `LastIndexOf(value)`
- `IsNullOrEmpty()`, `IsNullOrWhiteSpace()`
- All accept optional `StringComparison` parameter

**Split/Join:**
- `Split(char separator)` / `Split(char[] separators)` — returns `CyString[]`
- `CyString.Concat(a, b)` — static concatenation
- `CyString.Join(separator, values)` — static join

**Secure methods** (HMAC-based constant-time, never mark compromise):
- `SecureEquals(CyString other)`
- `SecureContains(string value)`
- `SecureStartsWith(string value)`
- `SecureEndsWith(string value)`

**Decryption:**
- `ToInsecureString()` — returns plaintext, marks compromised
- `[int index]` — returns `char`, marks compromised

### CyBytes

```csharp
using var cb = new CyBytes(new byte[] { 0x01, 0x02 });
int len = cb.Length;                       // metadata — no decryption
byte[] plain = cb.ToInsecureBytes();       // marks compromised

// Implicit/explicit conversions
CyBytes from = (CyBytes)someByteArray;
byte[] to = (byte[])from;
```

### CyGuid

```csharp
CyGuid cg = Guid.NewGuid();               // implicit conversion
Guid plain = (Guid)cg;                     // explicit — compromises
bool eq = (cg == new CyGuid(Guid.Empty));  // encrypted comparison
```

### CyDateTime

```csharp
CyDateTime cdt = DateTime.UtcNow;          // implicit conversion
DateTime plain = cdt.ToInsecureDateTime();  // marks compromised
bool before = (cdt < new CyDateTime(DateTime.MaxValue));
int cmp = cdt.CompareTo(otherCyDateTime);
```

---

## CyTypeBase — Common Functionality

All CyTypes inherit from `CyTypeBase<TNative>`, which provides:

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `Policy` | `SecurityPolicy` | Active security policy |
| `InstanceId` | `Guid` | Unique identifier per instance |
| `CreatedUtc` | `DateTime` | UTC creation timestamp |
| `IsDisposed` | `bool` | Whether `Dispose()` has been called |
| `IsCompromised` | `bool` | Whether plaintext has been exposed |
| `IsTainted` | `bool` | Whether taint has been propagated from another source |

### Methods

| Method | Description |
|--------|-------------|
| `RotateKeyAndReEncrypt()` | Atomically: decrypt with old key, derive new key via HKDF, re-encrypt |
| `ReEncryptWithCurrentKey()` | Re-encrypt without changing the key |
| `ToSecureBytes()` | Serialize to binary envelope (ciphertext + nonce + tag + HMAC-SHA512) |
| `ElevatePolicy(SecurityPolicy)` | Upgrade to a stricter policy (demotion not allowed) |
| `ApplyPolicy(SecurityPolicy)` | Change policy (demotion allowed only if `AllowDemotion` is set — marks tainted) |
| `MarkCompromised()` | Explicitly mark as compromised |
| `MarkTainted()` | Explicitly mark as tainted |
| `ClearTaint(string reason)` | Clear taint flag with documented reason |
| `Dispose()` | Zero secure buffers and release resources |
| `DisposeAsync()` | Async disposal |

### Events

| Event | Raised When |
|-------|-------------|
| `SecurityBreached` | Instance is marked compromised |
| `PolicyChanged` | Security policy changes |
| `TaintCleared` | Taint flag is cleared |

```csharp
using var cy = new CyInt(42);

cy.SecurityBreached += (sender, e) =>
    Console.WriteLine($"Compromised: {e}");

cy.PolicyChanged += (sender, e) =>
    Console.WriteLine($"Policy changed: {e}");

_ = cy.ToInsecureInt(); // fires SecurityBreached
```

---

## Security Policies

Four predefined policies control the security/performance tradeoff:

| Policy | Max Decryptions | Auto-Destroy | Taint Mode | Overflow Mode | Memory Protection |
|--------|----------------|--------------|------------|---------------|-------------------|
| `Maximum` | 10 | Yes | Strict | Checked | PinnedLocked |
| `Balanced` | 100 | No | Standard | Unchecked | PinnedLocked |
| `Performance` | Unlimited | No | Relaxed | Unchecked | PinnedLocked |
| `HomomorphicBasic` | Reserved for FHE | — | — | — | — |

**Stream properties:**

| Policy | Stream Chunk Size | Key Exchange | Stream Integrity |
|--------|-------------------|--------------|------------------|
| `Maximum` | 4 KB | Required | PerChunk + Footer HMAC |
| `Balanced` | 64 KB | Required | PerChunk + Footer HMAC |
| `Performance` | 256 KB | Not required | PerChunk only |

```csharp
// Maximum security — 10 decryptions max, auto-destroy, strict taint
using var secret = new CyInt(42, SecurityPolicy.Maximum);

// Balanced (default) — 100 decryptions, standard taint tracking
using var normal = new CyInt(42, SecurityPolicy.Balanced);

// Performance — unlimited decryptions, relaxed taint
using var fast = new CyInt(42, SecurityPolicy.Performance);

// HomomorphicBasic — reserved for FHE operations (requires CyTypes.Fhe package)
// using var fhe = new CyInt(42, SecurityPolicy.HomomorphicBasic);
```

### Custom Policies — SecurityPolicyBuilder

```csharp
var policy = new SecurityPolicyBuilder()
    .WithName("MyPolicy")
    .WithMaxDecryptionCount(50)
    .WithTaintMode(TaintMode.Strict)
    .WithAuditLevel(AuditLevel.AllOperations)
    .WithMemoryProtection(MemoryProtection.PinnedLocked)
    .WithOverflowMode(OverflowMode.Checked)          // throws on integer overflow
    .WithAutoDestroy(true)
    .WithAllowDemotion(false)                         // prevent policy downgrades
    .WithArithmeticMode(ArithmeticMode.Standard)
    .WithComparisonMode(ComparisonMode.Standard)
    .WithStringOperationMode(StringOperationMode.Standard)
    .WithKeyRotation(KeyRotationPolicy.Manual)
    .WithDecryptionRateLimit(10)                      // max 10 decryptions/second
    .WithKeyStoreMinimumCapability(KeyStoreCapability.InMemory)
    .Build();

using var cy = new CyInt(42, policy);
```

**Full SecurityPolicyBuilder API:**

| Method | Description |
|--------|-------------|
| `WithName(string)` | Display name for the policy |
| `WithMaxDecryptionCount(int)` | Max decryptions before auto-destroy (if enabled) |
| `WithTaintMode(TaintMode)` | Taint propagation mode: Strict, Standard, Relaxed |
| `WithAuditLevel(AuditLevel)` | Audit verbosity level |
| `WithMemoryProtection(MemoryProtection)` | Memory protection level |
| `WithOverflowMode(OverflowMode)` | Integer arithmetic: Checked or Unchecked |
| `WithAutoDestroy(bool)` | Enable auto-destroy on decryption limit |
| `WithAllowDemotion(bool)` | Allow policy demotion (marks tainted if true) |
| `WithArithmeticMode(ArithmeticMode)` | Arithmetic computation mode |
| `WithComparisonMode(ComparisonMode)` | Comparison mode for encrypted values |
| `WithStringOperationMode(StringOperationMode)` | String operation mode |
| `WithKeyRotation(KeyRotationPolicy)` | Key rotation policy |
| `WithDecryptionRateLimit(int)` | Max decryptions per second |
| `WithKeyStoreMinimumCapability(KeyStoreCapability)` | Minimum key store capability |
| `Build()` | Validate and build the policy |

> **Note:** FHE arithmetic modes (`HomomorphicBasic`, `HomomorphicFull`) are accepted by the builder with constraint validation: `HomomorphicBasic` requires at least `PinnedLocked` memory protection; `HomomorphicFull` additionally requires `AuditLevel.AllOperations`. FHE comparison (`HomomorphicCircuit`) and string (`HomomorphicEquality`) modes are fully supported and follow the same constraint validation. Stream properties (`StreamChunkSize`, `RequireKeyExchange`, `StreamIntegrity`) are currently configured via the predefined policies and are not yet exposed on `SecurityPolicyBuilder`.

## Taint Tracking

cyTypes tracks data compromise and taint propagation automatically:

```csharp
using var a = new CyInt(10);
_ = a.ToInsecureInt();          // a.IsCompromised = true

using var b = new CyInt(20);    // b is clean
using var c = a + b;            // c.IsTainted = true (compromised operand)

// Clear taint with documented reason
c.ClearTaint("verified-clean-by-security-review");
```

**Propagation rules:**

| Operation | Source State | Result State |
|-----------|-------------|--------------|
| `ToInsecure*()` | any | `IsCompromised = true` |
| `a + b` (either tainted) | tainted | `IsTainted = true` |
| `a + b` (both clean, diff policies) | clean | higher policy, clean |
| Policy demotion | any | `IsTainted = true` |
| `ClearTaint(reason)` | tainted | clean |

## Auto-Destroy

Instances can self-destruct after reaching a decryption threshold:

```csharp
var policy = new SecurityPolicyBuilder()
    .WithMaxDecryptionCount(3)
    .WithAutoDestroy(true)
    .Build();

var cy = new CyInt(42, policy);
_ = cy.ToInsecureInt(); // decryption 1
_ = cy.ToInsecureInt(); // decryption 2
_ = cy.ToInsecureInt(); // decryption 3 — triggers auto-destroy

cy.IsDisposed; // true — any further access throws ObjectDisposedException
```

## Key Rotation

cyTypes supports atomic key rotation with automatic re-encryption:

```csharp
using var cy = new CyInt(42);

// Atomically: decrypt → derive new key via HKDF → re-encrypt
cy.RotateKeyAndReEncrypt();

// Value is preserved with the new key
int value = cy.ToInsecureInt(); // 42

// Re-encrypt with the current key (no rotation)
cy.ReEncryptWithCurrentKey();
```

> **Important:** Never call `KeyManager.RotateKey()` directly — it destroys the old key, making existing ciphertext unreadable. Always use `RotateKeyAndReEncrypt()` which handles the full cycle atomically.

## Memory Protection

All encrypted data is stored in `SecureBuffer` instances that provide:

- **Pinned allocation**: `GC.AllocateArray<byte>(size, pinned: true)` — prevents GC relocation
- **OS-level locking**: `mlock` (Linux/macOS) / `VirtualLock` (Windows) — prevents paging to disk
- **Zeroing on dispose**: `CryptographicOperations.ZeroMemory` — no residual plaintext
- **Thread-safe dispose**: Atomic `Interlocked.CompareExchange` ensures dispose is safe under concurrent access

### Memory Forensics Tools

Two tools verify memory protection in practice:

```bash
# Demo 22 — in-process forensic comparison (lightweight, no ClrMD)
dotnet run --project examples/CyTypes.Examples -- 22

# Full forensic tool — interactive console with ClrMD heap analysis
dotnet run --project tests/CyTypes.Tools.MemoryForensics

# Generate static forensic report
dotnet run --project tests/CyTypes.Tools.MemoryForensics -- report forensic-report.txt

# Scan external process for plaintext patterns
dotnet run --project tests/CyTypes.Tools.MemoryForensics -- scan <pid> DEADBEEF
```

The forensic tools demonstrate:

| Verification | What it proves |
|-------------|----------------|
| Hex dump comparison | .NET stores plaintext; CyTypes stores only AES-256-GCM ciphertext |
| Pattern search | Plaintext byte patterns are never found in CyType encrypted buffers |
| Post-dispose scan | `SecureBuffer.Dispose()` zeroes all memory via `CryptographicOperations.ZeroMemory` |
| GC relocation proof | .NET strings relocate during compaction (ghost copies); CyTypes buffers are pinned |
| ClrMD heap walk | Live managed heap validation: all disposed `SecureBuffer` instances are zeroed |

---

## Roslyn Analyzer (CY0001-CY0004)

The `CyTypes.Analyzer` package provides compile-time security diagnostics:

| ID | Severity | Title | Description |
|----|----------|-------|-------------|
| **CY0001** | Warning | `ToInsecureValue()` called outside `[InsecureAccess]` context | Decryption calls should be wrapped in a method marked with `[InsecureAccess]` to document intentional exposure |
| **CY0002** | Warning | CyType used in string interpolation | String interpolation may leak security metadata — use explicit formatting |
| **CY0003** | Error | Explicit cast from CyType discards security tracking | Casting `(int)myCyInt` discards security state — value is compromised silently |
| **CY0004** | Warning | CyType not disposed | CyType instances hold sensitive memory and should use `using` or explicit `Dispose()` |

### Examples

```csharp
// CY0001 — Warning: ToInsecureValue() outside [InsecureAccess]
int value = myCyInt.ToInsecureInt(); // ⚠️ CY0001

[InsecureAccess]
int GetValue(CyInt cy) => cy.ToInsecureInt(); // ✅ OK

// CY0002 — Warning: CyType in string interpolation
Console.WriteLine($"Value: {myCyInt}"); // ⚠️ CY0002 — leaks metadata
Console.WriteLine("Value: " + myCyInt.ToInsecureInt()); // ✅ Explicit

// CY0003 — Error: Explicit cast discards tracking
int bad = (int)myCyInt; // ❌ CY0003 — silent compromise

// CY0004 — Warning: CyType not disposed
var cy = new CyInt(42); // ⚠️ CY0004 — no using/Dispose
using var ok = new CyInt(42); // ✅ OK
```

---

## FHE — Fully Homomorphic Encryption

The `CyTypes.Fhe` package provides FHE using **Microsoft SEAL** with the BFV scheme (exact integer arithmetic) and the CKKS scheme (approximate floating-point arithmetic) on ciphertexts.

### Current Status

- **BFV scheme**: Integer addition, subtraction, multiplication, and negation on encrypted data — without decryption
- **CKKS scheme**: Approximate floating-point addition, subtraction, multiplication, and negation on encrypted data (CyFloat, CyDouble, CyDecimal)
- **Comparisons**: `ComparisonMode.HomomorphicCircuit` computes encrypted differences via BFV/CKKS; the comparison verdict requires decryption of the difference to extract the sign
- **String equality**: `StringOperationMode.HomomorphicEquality` uses AES-SIV deterministic encryption for constant-time encrypted string equality (not FHE — leaks equality patterns)

### API

```csharp
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using Microsoft.Research.SEAL;

// 1. Initialize key manager
using var keyManager = new SealKeyManager();
var parms = new EncryptionParameters(SchemeType.BFV);
// Configure poly_modulus_degree, coeff_modulus, plain_modulus...
keyManager.Initialize(FheScheme.BFV, parms);

// 2. Create engine
using var engine = new SealBfvEngine(keyManager);

// 3. Encrypt values
byte[] encA = engine.Encrypt(42);
byte[] encB = engine.Encrypt(17);

// 4. Arithmetic on ciphertexts — no decryption needed
byte[] encSum  = engine.Add(encA, encB);       // 42 + 17 = 59
byte[] encDiff = engine.Subtract(encA, encB);  // 42 - 17 = 25
byte[] encProd = engine.Multiply(encA, encB);  // 42 * 17 = 714
byte[] encNeg  = engine.Negate(encA);          // -42

// 5. Decrypt result
long sum = engine.Decrypt(encSum);  // 59

// 6. Monitor noise budget (decreases with operations)
int budget = engine.GetNoiseBudget(encProd);
// When budget reaches 0, decryption will fail
```

### Key Management

```csharp
// Export keys for storage
SealKeyBundle bundle = keyManager.ExportKeyBundle();

// Properties
bool ready = keyManager.IsInitialized;
SEALContext ctx = keyManager.Context;
PublicKey pk = keyManager.PublicKey;
SecretKey sk = keyManager.SecretKey;
RelinKeys rlk = keyManager.RelinKeys;
```

---

## Benchmarks

The cyTypes wrapper adds **< 1% overhead** over raw AES-GCM encryption. HMAC and HKDF wrappers are equally lean. Full results from 112 core benchmarks (9 classes), 13 application benchmarks (3 classes), and streaming benchmarks (3 classes) are available in **[benchmarks.md](benchmarks.md)**.

| Operation | Overhead vs Native | Verdict |
|-----------|--------------------|---------|
| AES-GCM Encrypt/Decrypt (wrapper) | < 1% | Negligible |
| HKDF key derivation | ~1% | Negligible |
| HMAC compute | ~0% | Zero overhead |
| HMAC verify (constant-time) | 8-14% | Low |
| CyInt/CyString roundtrip | ~5.5 us | Acceptable |
| SecureBuffer alloc | 9-118x vs array | Expected (secure memory) |
| FHE BFV encrypt | ~817x vs AES-GCM | Expected (homomorphic) |
| JSON serialize (single) | ~108x | Expected (per-field encryption) |
| ChunkedCryptoEngine (64 KB encrypt) | 5,315 MB/s | High throughput (AES-NI) |
| CyStream round-trip (256 KB) | 1,024 MB/s | Includes header/footer/HMAC |
| CyFileStream round-trip (256 KB) | 493 MB/s | Includes disk I/O |

### Running Benchmarks

```bash
# Core benchmarks
dotnet run --project tests/CyTypes.Benchmarks -c Release

# Streaming benchmarks
dotnet run --project tests/CyTypes.Benchmarks -c Release -- --filter "*Stream*"

# Application benchmarks (API, EF Core, JSON)
dotnet run --project tests/CyTypes.Benchmarks.Application -c Release
```

### Performance Guidance

- **Maximum policy**: Highest overhead — checked arithmetic, strict taint propagation, low decryption limit. Use for secrets (API keys, SSNs, passwords).
- **Balanced policy**: Moderate overhead — standard taint, 100 decryptions. Good default for most sensitive data.
- **Performance policy**: Lowest overhead — relaxed taint, unlimited decryptions. Use for bulk data that needs encryption but not strict auditing.

---

## Cryptographic Primitives

| Component | Algorithm | Details |
|-----------|-----------|---------|
| Encryption | AES-256-GCM | 12-byte random nonce, 16-byte auth tag |
| Stream Encryption | Chunked AES-256-GCM | Per-chunk nonce, sequence number, key ratcheting every 2^20 chunks |
| Key Derivation | HKDF-SHA512 | Contextual info for key diversification |
| Key Exchange | ECDH P-256 + ML-KEM-1024 | Hybrid post-quantum key exchange (NIST P-256 + FIPS 203) |
| Secure Comparison | HMAC-SHA512 | `FixedTimeEquals` — immune to timing attacks |
| Stream Integrity | HMAC-SHA512 | Footer HMAC over header + all chunk GCM tags |
| Nonce Generation | `RandomNumberGenerator.Fill()` | CSPRNG per encryption |

## Project Structure

```
src/
├── CyTypes.Core                # Crypto engine, key management, memory, policy, audit
├── CyTypes.Primitives          # CyInt, CyString, CyBool, CyBytes, etc.
├── CyTypes.Analyzer            # Roslyn compile-time security checks (CY0001-CY0004)
├── CyTypes.Collections         # Encrypted collections (CyList, CyDictionary)
├── CyTypes.Logging             # Auto-redacting logger
├── CyTypes.EntityFramework     # EF Core value converters
├── CyTypes.DependencyInjection # IServiceCollection extensions
├── CyTypes.Fhe                 # Fully Homomorphic Encryption (Microsoft SEAL)
└── CyTypes.Streams             # Encrypted streaming (file, IPC, TCP)

tests/
├── CyTypes.Core.Tests
├── CyTypes.Primitives.Tests
├── CyTypes.Collections.Tests
├── CyTypes.Analyzer.Tests
├── CyTypes.Logging.Tests
├── CyTypes.EntityFramework.Tests
├── CyTypes.DependencyInjection.Tests
├── CyTypes.Fhe.Tests
├── CyTypes.Security.Tests            # Security/compliance test suite
├── CyTypes.Streams.Tests
├── CyTypes.Benchmarks                # Core micro-benchmarks (BenchmarkDotNet)
├── CyTypes.Benchmarks.Application    # Application-level benchmarks (API, EF Core, JSON)
├── CyTypes.Tools.HeapAnalysis        # Memory analysis tool (external process)
└── CyTypes.Tools.MemoryForensics     # Full forensic tool (interactive + report)

examples/
├── CyTypes.Sample.Console            # End-to-end console walkthrough
├── CyTypes.Sample.WebApi             # ASP.NET Core minimal API with EF Core
└── CyTypes.Examples                  # 22 interactive demo scenarios

docs/
├── hello-world.md                    # 5-minute minimal introduction
├── getting-started.md                # Full feature overview
├── (10 topic guides)                 # FHE, PQC, streaming, EF Core, etc.
└── compliance/                       # FIPS, NIST, SOC2/PCI/GDPR documentation

nupkgs/                               # Built NuGet packages
```

## Building & Testing

```bash
# Restore and build
dotnet build cyTypes.sln

# Run all tests
dotnet test cyTypes.sln

# Run with coverage
dotnet test cyTypes.sln --collect:"XPlat Code Coverage"

# Run benchmarks (Release mode required for accurate results)
dotnet run --project tests/CyTypes.Benchmarks -c Release
```

## Roadmap

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Core crypto, primitives, taint, policies | Complete |
| 2 | Roslyn analyzer, secure collections, auto-redacting logging, EF Core | Complete |
| 3a | FHE — Microsoft SEAL BFV integration (`CyTypes.Fhe` package) | Complete |
| 3b | FHE — CKKS support, comparison/string operations on ciphertexts | Complete |
| 3c | PQC — ML-KEM-1024 key encapsulation (hybrid ECDH + ML-KEM key exchange) | Complete |
| 4 | Encrypted streaming — chunked AES-256-GCM, file I/O, IPC (named pipes), TCP, hybrid key exchange | Complete |

> **Phase 3 status:** Phase 3a (BFV) and Phase 3b (CKKS + comparisons + string equality) are complete. The `CyTypes.Fhe` package provides `SealBfvEngine` for exact integer arithmetic and `SealCkksEngine` for approximate floating-point arithmetic (CyFloat, CyDouble, CyDecimal) on encrypted data. `ComparisonMode.HomomorphicCircuit` enables comparisons via encrypted difference with deferred sign extraction. `StringOperationMode.HomomorphicEquality` uses AES-SIV deterministic encryption for constant-time encrypted string equality. The `HomomorphicFull` policy preset enables all FHE features. ML-KEM-1024 key encapsulation is fully integrated into the streaming layer via hybrid ECDH P-256 + ML-KEM-1024 key exchange.

## Contributing

Contributions are welcome. Please read [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy before reporting security issues.

For general contributions:
1. Fork the repository
2. Create a feature branch
3. Ensure all tests pass: `dotnet test cyTypes.sln`
4. Submit a pull request

## License

[MIT](LICENSE) — Copyright 2026 Matteo Sala (cysalazar@cysalazar.com)
