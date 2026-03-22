# NIST CAVP HKDF Mapping — cyTypes

> **Disclaimer**: This is a self-assessment mapping of test coverage to NIST CAVP categories, not a formal CAVP validation certificate. Formal validation requires submission to an accredited laboratory.

## Algorithm Implementation
- **Algorithm**: HKDF-SHA512 (RFC 5869)
- **Hash Function**: SHA-512
- **Implementation**: `CyTypes.Core.Crypto.HkdfKeyDerivation`

## Test Vector Coverage

| Source | Description | Status |
|--------|-------------|--------|
| RFC 5869 Structure (SHA-512) | 3 vectors adapted from Appendix A with SHA-512 outputs | Covered |
| KAT Self-Test | Fixed IKM/salt/info with precomputed output | Covered |
| Determinism | Same inputs produce identical outputs | Covered |
| Edge Cases | Empty salt, empty info, minimal IKM | Covered |

## RFC 5869 Adaptation Notes
RFC 5869 Appendix A provides test vectors only for HKDF-SHA256.
The SHA-512 expected outputs used in `HkdfSha512RfcVectorTests` are
precomputed using the .NET `System.Security.Cryptography.HKDF` reference
implementation and verified for cross-platform consistency.

## HMAC-SHA512 Test Coverage
- **Implementation**: `CyTypes.Core.Crypto.HmacComparer`
- **KAT**: Fixed key + data with precomputed 64-byte output
- **Constant-time comparison**: `CryptographicOperations.FixedTimeEquals`

## SP 800-108 Alignment
The HKDF implementation follows the extract-then-expand paradigm:
1. **Extract**: HMAC-SHA512(salt, IKM) → PRK
2. **Expand**: HMAC-SHA512(PRK, info || counter) → OKM
