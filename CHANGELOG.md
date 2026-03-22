# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.2.1] - 2026-03-22

### Fixed
- FHE integration test race condition: `CkksIntegrationTests` and `FheIntegrationTests` now run in a serialized xUnit collection to prevent parallel `FheEngineProvider.Configure()`/`Reset()` conflicts

## [2.2.0] - 2026-03-22

### Added
- `CyTypes` meta-package — single NuGet install for all components
- 7 new interactive demos: FHE BFV, PQC ML-KEM, Collections, DI+Logging, Overflow+KeyTTL, JSON Serialization
- 2 sample projects: `CyTypes.Sample.WebApi` (DI + EF Core + Logging) and `CyTypes.Sample.Console` (end-to-end walkthrough)
- Documentation: `pqc-guide.md`, `collections-guide.md`, `analyzer-guide.md`, `di-fhe-guide.md`
- Updated `fhe-guide.md` with CKKS, homomorphic comparisons, and AES-SIV string equality
- Updated `getting-started.md` with Phase 3+ features overview and guide index
- 41 new tests: Streams (32→55), EF Core (34→43), Analyzer (10→19)
- EF Core persistence tests for all 10 CyType primitives (was 5)
- `IEquatable<T>` on all 10 primitive types with `Equals(T?)`, `Equals(object?)`, and `GetHashCode()` consistency
- `IComparable<T>` on `CyBool`, `CyString` (ordinal), `CyBytes` (lexicographic), and `CyGuid`
- Comparison operators (`<`, `>`, `<=`, `>=`) on `CyBool`, `CyString`, `CyBytes`, and `CyGuid`
- Equality operators (`==`, `!=`) on `CyBytes` and `CyGuid`
- `RotateKeyAndReEncrypt()` — atomic decrypt→rotate→re-encrypt for safe key rotation
- `RotateKey()` alias for `RotateKeyAndReEncrypt()`
- `ReEncryptWithCurrentKey()` — re-encrypts data without rotating the key
- Thread-safety tests for `SecureBuffer` (concurrent dispose, dispose+access races)
- Comprehensive XML documentation on all public APIs across all projects
- `OverflowMode` enum (`Checked` / `Unchecked`) for integer arithmetic overflow control
- `SecurityPolicy.Overflow` property and `SecurityPolicyBuilder.WithOverflowMode()` method
- `CyInt` and `CyLong` operators now respect `OverflowMode.Checked` (throws `OverflowException`)
- `SecurityPolicy.Maximum` now uses `OverflowMode.Checked` by default
- Input size validation in `CyString` and `CyBytes` constructors (16 MB limit, consistent with deserialization)
- Key TTL/expiration support in `KeyManager` with `KeyExpiredException`
- `KeyStoreCapability` enum and explicit fallback rejection in `PlatformKeyStoreFactory`
- Decryption rate limiting (`DecryptionRateLimit` in `SecurityPolicy`)
- `RateLimitExceededException` for brute-force timing protection
- `IComparable<T>` on all numeric types and `CyDateTime`
- `IFormattable` on `CyTypeBase` (returns redacted output)
- System.Text.Json converters for all CyTypes (`CyTypesJsonExtensions.AddCyTypesConverters()`)
- Secure serialization format with HMAC-SHA512 integrity verification
- EF Core value converters (`CyTypes.EntityFramework` package)
- Auto-redacting logging (`CyTypes.Logging` package)
- NuGet publish workflow on `v*` tags
- Code coverage reporting in CI with 80% threshold
- Encrypted collections: `CyList<T>` and `CyDictionary<TKey, TValue>`
- Roslyn analyzer with diagnostics CY0001-CY0005
- Implicit widening conversions between numeric CyTypes
- `CHANGELOG.md` and `.gitattributes`

### Changed
- `SecureBuffer.Dispose()` is now thread-safe via `Interlocked.CompareExchange` (was non-atomic `bool`)
- `SecurityContext` flags (`IsCompromised`, `IsTainted`, `IsAutoDestroyed`) now use `Volatile.Read`/`Interlocked.Exchange` for cross-thread visibility
- `DecryptValue()` now zeroes ciphertext copies in all paths (including exceptions) via try/finally
- Removed CS1591 suppression — all public members now have XML documentation
- Version now centralized in `Directory.Build.props`
- `SecurityPolicy.Maximum` now includes `DecryptionRateLimit=10`, `KeyStoreMinimumCapability=OsProtected`, and `OverflowMode.Checked`
- Predefined policies (`Maximum`, `Balanced`) now use `SecureEnclave` arithmetic instead of FHE modes (FHE reserved for Phase 3)
- `SecurityPolicyBuilder` now rejects FHE modes (`HomomorphicFull`, `HomomorphicBasic`, `HomomorphicCircuit`, `HomomorphicEquality`) with `PolicyViolationException`
- `SecurityPolicyBuilder` defaults updated to `SecureEnclave` / `HmacBased` (previously `HomomorphicBasic`)
- `BinarySerializer.MaxVariableLengthBytes` is now `public` (was `internal`)
- `PlatformKeyStoreFactory.Create()` now accepts `minimumCapability` parameter

### Fixed
- CKKS floating-point demo (15) was not registered in the interactive examples menu

## [1.0.0] - 2026-03-19

### Added
- Phase 1 complete: 10 encrypted primitive types (CyInt, CyLong, CyFloat, CyDouble, CyDecimal, CyBool, CyString, CyBytes, CyGuid, CyDateTime)
- AES-256-GCM encryption with HKDF-SHA512 key derivation
- Security policies (Maximum, Balanced, Performance) with fluent builder
- Taint tracking and auto-destroy on decryption threshold
- Memory protection with pinned + locked + zeroed-on-dispose buffers
- Platform key stores (macOS Keychain, Windows DPAPI, Linux libsecret)
- Security audit system with configurable sinks
- Cross-policy resolution with 5 rules
- Full arithmetic and comparison operators with taint propagation
