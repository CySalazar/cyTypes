# EF Core Integration Guide

## Overview

The `CyTypes.EntityFramework` package provides EF Core value converters for all CyType primitives.
Values are decrypted when persisted to the database and re-encrypted when materialized from query results.

## Installation

```bash
dotnet add package CyTypes.EntityFramework
```

## Setup

Register all CyTypes converters in your `DbContext`:

```csharp
using CyTypes.EntityFramework;

public class AppDbContext : DbContext
{
    public DbSet<Patient> Patients => Set<Patient>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.UseCyTypes(); // registers all 10 value converters
    }
}
```

The `UseCyTypes()` extension method registers converters for:
`CyInt`, `CyLong`, `CyFloat`, `CyDouble`, `CyDecimal`, `CyBool`,
`CyString`, `CyGuid`, `CyDateTime`, `CyBytes`.

## Entity Configuration

Define entities using CyType properties:

```csharp
public class Patient : IDisposable
{
    public int Id { get; set; }
    public CyString Name { get; set; } = null!;
    public CyString Ssn { get; set; } = null!;
    public CyInt Age { get; set; } = null!;
    public CyDateTime DateOfBirth { get; set; } = null!;

    public void Dispose()
    {
        Name?.Dispose();
        Ssn?.Dispose();
        Age?.Dispose();
        DateOfBirth?.Dispose();
    }
}
```

## How Converters Work

Each converter (e.g., `CyIntValueConverter`) defines two-way conversion:

- **To database**: calls `ToInsecureInt()` to extract the plaintext value for storage
- **From database**: constructs a new `CyInt(value)` with the default policy

```csharp
// CyIntValueConverter internally does:
//   cy => cy.ToInsecureInt()         (write to DB)
//   value => new CyInt(value)        (read from DB)
```

## Query Considerations

Since CyType values are decrypted for storage, database queries operate on plaintext columns.
This means:

- **WHERE clauses work normally** -- the database sees plain `int`, `nvarchar`, etc.
- **Indexing works** -- standard database indexes apply to the stored plaintext
- **Encryption is application-side** -- the database stores unencrypted values

If you need database-level encryption, combine CyTypes with Always Encrypted or
Transparent Data Encryption (TDE) at the database layer.

## Custom Policy on Materialization

Entities materialize with `SecurityPolicy.Default` (Balanced). To apply a different
policy, set it after materialization:

```csharp
var patient = await db.Patients.FindAsync(id);
patient.Ssn.ElevatePolicy(SecurityPolicy.Maximum);
```

## Example: Full DbContext

```csharp
using CyTypes.EntityFramework;
using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore;

public class SecureDbContext : DbContext
{
    public DbSet<Account> Accounts => Set<Account>();

    public SecureDbContext(DbContextOptions<SecureDbContext> options) : base(options) { }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.UseCyTypes();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Account>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.Email).IsRequired().HasMaxLength(256);
            e.Property(a => a.Balance).HasPrecision(18, 2);
        });
    }
}

public class Account : IDisposable
{
    public int Id { get; set; }
    public CyString Email { get; set; } = null!;
    public CyDecimal Balance { get; set; } = null!;

    public void Dispose()
    {
        Email?.Dispose();
        Balance?.Dispose();
    }
}
```

## Disposal

Remember to dispose CyType properties when the entity is no longer needed.
EF Core's change tracker holds references to entities -- call `Dispose()` on
entities when removing them from tracking or when the DbContext is disposed.
