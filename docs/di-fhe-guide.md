# Dependency Injection + FHE Integration Guide

## Overview

The `AddCyTypesFhe()` and related DI extension methods automatically bridge the gap between DI-resolved FHE engines and the static `FheEngineProvider` that `CyTypeBase` uses internally. You don't need to call `FheEngineProvider.Configure()` manually when using DI.

## Basic DI + FHE Setup

```csharp
using CyTypes.DependencyInjection;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;

var builder = WebApplication.CreateBuilder(args);

// Register core cyTypes services
builder.Services.AddCyTypes(options =>
{
    options.DefaultPolicy = SecurityPolicy.Balanced;
    options.EnableRedactingLogger = true;
});

// Register BFV engine — FheEngineProvider.Configure() is called internally
builder.Services.AddCyTypesFhe(sp =>
{
    var keyManager = new SealKeyManager();
    keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
    return new SealBfvEngine(keyManager);
});
```

When the `IFheEngine` is first resolved from the container, `AddCyTypesFhe` automatically calls `FheEngineProvider.Configure(engine)`. After that, any `CyInt` or `CyLong` created with `SecurityPolicy.HomomorphicBasic` will use the registered engine.

## Full FHE Stack (BFV + CKKS + Comparisons + String Equality)

```csharp
// BFV for integer arithmetic
builder.Services.AddCyTypesFhe(sp =>
{
    var km = new SealKeyManager();
    km.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
    return new SealBfvEngine(km);
});

// CKKS for floating-point arithmetic
builder.Services.AddCyTypesCkks(sp =>
{
    var km = new SealKeyManager();
    km.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
    return new SealCkksEngine(km);
});

// Homomorphic comparisons (requires both BFV and CKKS)
builder.Services.AddCyTypesHomomorphicComparison(sp =>
{
    var bfv = sp.GetRequiredService<IFheEngine>();
    var ckks = sp.GetRequiredService<IFheFloatingPointEngine>();
    return new SealComparisonEngine((SealBfvEngine)bfv, (SealCkksEngine)ckks);
});

// String equality (AES-SIV)
builder.Services.AddCyTypesHomomorphicStringEquality(sp =>
    AesSivEngine.CreateWithRandomKey());
```

## How It Works Internally

Each `AddCyTypes*` method registers a singleton factory that:

1. Calls your factory function to create the engine
2. Calls `FheEngineProvider.Configure(engine)` to register it globally
3. Returns the engine for DI resolution

```
AddCyTypesFhe(factory)
  └─ TryAddSingleton<IFheEngine>(sp => {
       var engine = factory(sp);
       FheEngineProvider.Configure(engine);  // <-- automatic
       return engine;
     })
```

This means:
- You **never** need to call `FheEngineProvider.Configure()` manually when using DI
- The engine is lazily initialized on first resolution
- The static provider and DI container always stay in sync

## Important: Resolve to Trigger Registration

The `FheEngineProvider.Configure()` call happens when the service is first resolved, not at registration time. In a WebAPI, this typically happens on the first request. If you need the engine available immediately at startup:

```csharp
var app = builder.Build();

// Force eager initialization
_ = app.Services.GetRequiredService<IFheEngine>();
```

## Cleanup

In DI scenarios, engine disposal is handled by the DI container when the application shuts down. You don't need to call `FheEngineProvider.Reset()` manually.

## Available DI Extension Methods

| Method | Registers | FheEngineProvider method |
|--------|-----------|------------------------|
| `AddCyTypes()` | Core services, policy, crypto, audit | — |
| `AddCyTypesFhe()` | `IFheEngine` (BFV) | `Configure(IFheEngine)` |
| `AddCyTypesCkks()` | `IFheFloatingPointEngine` (CKKS) | `Configure(IFheFloatingPointEngine)` |
| `AddCyTypesHomomorphicComparison()` | `IFheComparisonEngine` | `Configure(IFheComparisonEngine)` |
| `AddCyTypesHomomorphicStringEquality()` | `IDeterministicEncryptionEngine` | `Configure(IDeterministicEncryptionEngine)` |

## Without DI (Manual Setup)

If you're not using DI, you must configure the provider manually:

```csharp
var keyManager = new SealKeyManager();
keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
var engine = new SealBfvEngine(keyManager);

FheEngineProvider.Configure(engine);

try
{
    // Use CyTypes with FHE...
}
finally
{
    FheEngineProvider.Reset();
    engine.Dispose();
    keyManager.Dispose();
}
```
