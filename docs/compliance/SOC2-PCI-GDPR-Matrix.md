# Compliance Matrix — cyTypes

> **Disclaimer**: This is a self-assessment mapping of cyTypes capabilities to compliance framework requirements, not a formal certification or audit report. Achieving SOC 2, PCI DSS, or GDPR compliance requires independent assessment of your complete system — not just the cryptographic library.

## SOC 2 Type II

| Control | Requirement | cyTypes Implementation |
|---------|-------------|----------------------|
| CC6.1 | Encryption of sensitive data | AES-256-GCM via CyTypes primitives |
| CC6.4 | Encryption key management | KeyManager with TTL and rotation |
| CC6.7 | Data disposal | SecureBuffer zeroing on dispose |
| CC7.2 | Security monitoring | SecurityAuditor event logging |
| CC8.1 | Change management | CI/CD with security test gates |

## PCI DSS v4.0

| Requirement | Description | cyTypes Implementation |
|------------|-------------|----------------------|
| 3.5 | Protect stored account data | Transparent encryption via CyTypes |
| 3.6 | Protect cryptographic keys | SecureBuffer + mlock + zeroing |
| 3.7 | Key management procedures | KeyManager with rotation TTL |
| 4.2 | Protect PAN in transit | AES-256-GCM with AEAD |
| 6.2 | Secure development | CI security tests, code analysis |
| 10.2 | Audit trail | SecurityAuditor events |

## GDPR

| Article | Requirement | cyTypes Implementation |
|---------|-------------|----------------------|
| Art. 25 | Data protection by design | Encryption-first via CyTypes |
| Art. 32 | Security of processing | AES-256-GCM, HKDF-SHA512 |
| Art. 32(1)(a) | Pseudonymisation/encryption | CyString, CyInt transparent encryption |
| Art. 17 | Right to erasure | Dispose() + SecureBuffer zeroing |
| Art. 33 | Breach notification | SecurityContext compromise tracking |

## Algorithm Compliance Summary

| Standard | Required | cyTypes |
|----------|----------|---------|
| NIST SP 800-131A | AES-128+ | AES-256 |
| NIST SP 800-38D | GCM mode | AES-GCM |
| NIST SP 800-56C | Key derivation | HKDF-SHA512 |
| FIPS 198-1 | HMAC | HMAC-SHA512 |
| PCI DSS 3.6.1 | 256-bit keys | 256-bit AES keys |
| GDPR Art. 32 | State of the art | AES-256-GCM (AEAD) |
