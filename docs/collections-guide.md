# Encrypted Collections Guide

## Overview

`CyTypes.Collections` provides `CyList<T>` and `CyDictionary<TKey, TValue>` -- encrypted collection types that automatically manage the lifecycle of their `ICyType` elements. When an element is removed or the collection is disposed, the element's secure memory is zeroed.

## Installation

```bash
dotnet add package CyTypes.Collections
```

## CyList\<T\>

A strongly-typed, disposable list for `ICyType` elements.

### Basic Usage

```csharp
using CyTypes.Collections;
using CyTypes.Primitives;

using var list = new CyList<CyInt>();
list.Add(new CyInt(10));
list.Add(new CyInt(20));
list.Add(new CyInt(30));

Console.WriteLine(list.Count);     // 3
Console.WriteLine(list[0]);        // [CyInt:Encrypted|...]
```

### AddRange

```csharp
list.AddRange(new[] { new CyInt(40), new CyInt(50) });
```

### Encrypted Aggregation

Work on encrypted values as long as possible — decrypt only at the end:

```csharp
// Sum all elements without exposing individual values
using var total = list.Aggregate((acc, x) => acc + x);

// Decrypt only the final result
Console.WriteLine(total.ToInsecureInt()); // 60
```

### RemoveAll -- Dispose Matching Elements

Use CyInt comparison operators — the predicate compares encrypted values
via the policy's `ComparisonMode`, without exposing plaintext to your code:

```csharp
using var threshold = new CyInt(25);
int removed = list.RemoveAll(x => x > threshold);
// Removed elements are automatically disposed (memory zeroed)
```

### DetachAt -- Remove Without Disposing

```csharp
var item = list.DetachAt(0);
// item is NOT disposed -- you own it now
// ... use item ...
item.Dispose(); // your responsibility
```

### Sort and FindAll

CyInt implements `IComparable<CyInt>` — sort and filter without calling `ToInsecure*()`:

```csharp
// Sort using CyInt's built-in encrypted comparison
list.Sort((a, b) => a.CompareTo(b));

// Filter using encrypted comparison operators
using var minValue = new CyInt(10);
using var filtered = list.FindAll(x => x > minValue);
// filtered is a new CyList with shared references (not cloned)
```

### ForEach

```csharp
// Printing requires decryption — this is the appropriate place to decrypt
list.ForEach(item => Console.Write($"{item.ToInsecureInt()} "));
```

## CyDictionary\<TKey, TValue\>

A dictionary mapping keys to `ICyType` values with automatic disposal.

### Basic Usage

```csharp
using var dict = new CyDictionary<string, CyString>();
dict["email"] = new CyString("alice@example.com");
dict["ssn"]   = new CyString("123-45-6789");

Console.WriteLine(dict.Count);           // 2
Console.WriteLine(dict.ContainsKey("email")); // True

if (dict.TryGetValue("ssn", out var ssn))
{
    Console.WriteLine(ssn.ToInsecureString());
}
```

### Overwrite Disposes Old Value

```csharp
dict["email"] = new CyString("bob@example.com");
// The old "alice@example.com" CyString is automatically disposed
```

### Detach -- Remove Without Disposing

```csharp
var detached = dict.Detach("email");
// detached is NOT disposed -- you own it now
```

## Minimizing Decryption — Best Practices

The examples above demonstrate two principles:

1. **Aggregate, sort, and filter on encrypted values** using operators (`+`, `>`, `CompareTo`) — these work through the policy's comparison and arithmetic modes without exposing plaintext to your code.
2. **Decrypt only at system boundaries** — when you need to display, serialize, or return a value to an external consumer.

Pattern to avoid:

```csharp
// Bad — decrypts every element just to find the max
var max = list.OrderByDescending(x => x.ToInsecureInt()).First();
```

Preferred:

```csharp
// Good — uses encrypted comparison, decrypts only the final result
list.Sort((a, b) => b.CompareTo(a));
Console.WriteLine(list[0].ToInsecureInt());
```

## ToCyList LINQ Extension

Convert any `IEnumerable<T>` of `ICyType` elements to a `CyList<T>`:

```csharp
using CyTypes.Collections;

using var numbers = Enumerable.Range(1, 10)
    .Select(n => new CyInt(n))
    .ToCyList();
```

## Disposal Semantics

| Operation       | Element disposed? |
|-----------------|-------------------|
| `Remove(item)`  | Yes               |
| `RemoveAt(i)`   | Yes               |
| `RemoveAll(p)`  | Yes (matching)    |
| `Clear()`       | Yes (all)         |
| `Dispose()`     | Yes (all)         |
| `DetachAt(i)`   | **No** (caller)   |
| `Detach(key)`   | **No** (caller)   |
| Indexer set      | Yes (old value)   |

## Important Notes

- Elements are added by reference, not cloned. Do not dispose an element while it's still in the collection.
- `FindAll()` returns a new list with shared references -- disposing the result does NOT dispose the original elements.
- Keys in `CyDictionary` are plain values (e.g., `string`, `int`) -- only values need to be `ICyType`.
- The Roslyn analyzer diagnostic **CY0005** warns against using `ICyType` instances as dictionary keys because they use identity-based hash codes.
