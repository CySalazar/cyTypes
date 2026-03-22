# Migration Guide

## Overview

This guide covers migrating from plain .NET types to CyTypes. The primary changes are:
construction wraps values in encrypted containers, decryption is explicit, and disposal is required.

## Type Mappings

| Plain Type   | CyType       | Notes                                    |
|-------------|--------------|------------------------------------------|
| `int`       | `CyInt`      | Supports arithmetic operators            |
| `long`      | `CyLong`     | Supports arithmetic operators            |
| `float`     | `CyFloat`    | IEEE 754 semantics preserved             |
| `double`    | `CyDouble`   | IEEE 754 semantics preserved             |
| `decimal`   | `CyDecimal`  | Always throws on overflow                |
| `bool`      | `CyBool`     | Supports logical operators               |
| `string`    | `CyString`   | String methods available (Contains, etc.)|
| `Guid`      | `CyGuid`     | Equality and formatting                  |
| `DateTime`  | `CyDateTime` | Comparison operators                     |
| `byte[]`    | `CyBytes`    | Raw binary data                          |

## Construction

```csharp
// Before
int userId = 42;
string email = "alice@example.com";

// After
using var userId = new CyInt(42);
using var email = new CyString("alice@example.com");

// With implicit conversion
CyInt userId = 42;  // implicit, but you must still dispose
```

## Reading Values

Decryption is intentionally verbose. The `ToInsecure*()` name reminds you
that plaintext is leaving the encrypted enclave.

```csharp
// Before
Console.WriteLine(userId);

// After -- explicit decryption required
Console.WriteLine(userId.ToInsecureInt());

// ToString() is always safe (returns redacted output)
Console.WriteLine(userId); // [CyInt:Encrypted|Policy=Balanced|Compromised=False]
```

## Arithmetic and Comparisons

Operators work directly on CyTypes. Results are new encrypted instances.

```csharp
using var a = new CyInt(10);
using var b = new CyInt(20);
using var sum = a + b;        // CyInt, encrypted
bool isGreater = a > b;       // comparison decrypts internally
```

## Handling Dispose

Every CyType must be disposed. The recommended patterns:

```csharp
// Pattern 1: using statement
using var secret = new CyString("sensitive");

// Pattern 2: using block (when you need narrower scope)
using (var temp = new CyInt(42))
{
    Process(temp);
} // disposed here

// Pattern 3: in a class that owns CyType fields
public class UserRecord : IDisposable
{
    private CyString _email;
    private CyInt _age;

    public UserRecord(string email, int age)
    {
        _email = new CyString(email);
        _age = new CyInt(age);
    }

    public void Dispose()
    {
        _email?.Dispose();
        _age?.Dispose();
    }
}
```

## Policy Selection

| Scenario                          | Recommended Policy              |
|-----------------------------------|---------------------------------|
| General application data          | `SecurityPolicy.Balanced`       |
| PII, financial, healthcare        | `SecurityPolicy.Maximum`        |
| High-throughput, low-sensitivity  | `SecurityPolicy.Performance`    |
| Compute on encrypted data         | `SecurityPolicy.HomomorphicBasic`|
| Custom requirements               | `SecurityPolicyBuilder`         |

```csharp
// Apply policy at construction
using var ssn = new CyString("123-45-6789", SecurityPolicy.Maximum);
```

## Collections

CyTypes provides `CyList<T>` and `CyDictionary<TKey, TValue>` for encrypted collections:

```csharp
using var list = new CyList<CyInt>();
list.Add(new CyInt(1));
list.Add(new CyInt(2));

using var dict = new CyDictionary<CyString, CyInt>();
dict.Add(new CyString("age"), new CyInt(30));
```

## JSON Serialization

Register converters for System.Text.Json:

```csharp
var options = new JsonSerializerOptions();
options.AddCyTypesConverters(); // extension from CyTypes.Primitives
```

## Performance Considerations

- **Construction cost** -- each CyType instance generates a unique key and encrypts the value. Batch creation of many small values has overhead.
- **Arithmetic** -- each operation decrypts operands, computes, and re-encrypts the result. For tight loops, consider decrypting once, computing, then re-encrypting.
- **Memory** -- `PinnedLocked` uses OS-level mlock, which has per-process limits. Monitor with `ulimit -l`.
- **Key rotation** -- automatic rotation adds latency on the triggering operation. Tune `EveryNOperations` based on your access patterns.
