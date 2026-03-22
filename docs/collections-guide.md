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

foreach (var item in list)
{
    Console.WriteLine(item.ToInsecureInt());
}
```

### AddRange

```csharp
list.AddRange(new[] { new CyInt(40), new CyInt(50) });
```

### RemoveAll -- Dispose Matching Elements

```csharp
int removed = list.RemoveAll(x => x.ToInsecureInt() > 25);
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

```csharp
list.Sort((a, b) => a.ToInsecureInt().CompareTo(b.ToInsecureInt()));

using var filtered = list.FindAll(x => x.ToInsecureInt() > 10);
// filtered is a new CyList with shared references (not cloned)
```

### ForEach

```csharp
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
