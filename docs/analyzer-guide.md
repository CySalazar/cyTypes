# Roslyn Analyzer Guide

## Overview

`CyTypes.Analyzer` is a Roslyn-based compile-time analyzer that detects common security mistakes when using CyTypes. It ships as a NuGet analyzer package and runs during compilation.

## Installation

```bash
dotnet add package CyTypes.Analyzer
```

The analyzer activates automatically -- no configuration needed.

## Diagnostics

### CY0001 -- Insecure Access Outside Marked Context

**Severity:** Warning

Detects calls to `ToInsecureInt()`, `ToInsecureString()`, and other `ToInsecure*()` methods outside a method annotated with `[InsecureAccess]`.

```csharp
// Warning CY0001
void Process(CyInt value)
{
    int x = value.ToInsecureInt(); // CY0001: not in [InsecureAccess] context
}

// No warning
[InsecureAccess]
void ProcessInsecure(CyInt value)
{
    int x = value.ToInsecureInt(); // OK -- explicitly marked
}
```

**Why:** Forces developers to explicitly acknowledge plaintext access. Code review can then focus on `[InsecureAccess]` methods.

### CY0002 -- CyType in String Interpolation

**Severity:** Warning

Detects CyType instances used in string interpolation or `string.Format()`.

```csharp
using var secret = new CyString("password");
Console.WriteLine($"Token: {secret}"); // CY0002: CyType in interpolation
```

**Why:** While `ToString()` returns redacted output, the interpolation pattern suggests the developer may expect plaintext. This diagnostic prompts review.

### CY0003 -- Explicit Cast Discards Security

**Severity:** Warning

Detects explicit casts from CyTypes to their native types (e.g., `(int)cyInt`).

```csharp
using var val = new CyInt(42);
int x = (int)val; // CY0003: cast discards security tracking
```

**Why:** Casting bypasses the `ToInsecure*()` naming convention, making accidental decryption harder to spot in code review.

### CY0004 -- CyType Not Disposed

**Severity:** Warning

Detects CyType variables that go out of scope without being disposed.

```csharp
void Process()
{
    var secret = new CyInt(42); // CY0004: not disposed
    // secret goes out of scope without using/Dispose()
}
```

**Fix:** Use `using` or call `Dispose()`:

```csharp
void Process()
{
    using var secret = new CyInt(42); // OK
}
```

**Why:** Undisposed CyTypes delay secure memory zeroing until the finalizer runs, extending the exposure window.

### CY0005 -- CyType as Dictionary Key

**Severity:** Warning

Detects CyType instances used as dictionary keys or in `HashSet<T>`.

```csharp
var dict = new Dictionary<CyInt, string>(); // CY0005: CyType as key
```

**Why:** CyTypes use identity-based `GetHashCode()` (not value-based), so two `CyInt(42)` instances produce different hashes. Use plain types as keys and CyTypes as values, or use `CyDictionary<TKey, TValue>`.

## Suppressing Diagnostics

If you intentionally want to suppress a diagnostic:

```csharp
#pragma warning disable CY0001
int x = secret.ToInsecureInt();
#pragma warning restore CY0001
```

Or in `.editorconfig`:

```ini
[*.cs]
dotnet_diagnostic.CY0001.severity = none
```

## Integration with CI

The analyzer runs as part of `dotnet build`. To treat warnings as errors in CI:

```xml
<PropertyGroup>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
</PropertyGroup>
```

Or selectively:

```xml
<PropertyGroup>
    <WarningsAsErrors>CY0001;CY0004</WarningsAsErrors>
</PropertyGroup>
```
