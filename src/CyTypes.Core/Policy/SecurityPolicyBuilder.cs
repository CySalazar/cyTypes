using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Policy;

/// <summary>
/// Fluent builder for constructing <see cref="SecurityPolicy"/> instances with custom component settings.
/// </summary>
public sealed class SecurityPolicyBuilder
{
    private string _name = "Custom";
    private ArithmeticMode _arithmetic = ArithmeticMode.SecureEnclave;
    private ComparisonMode _comparison = ComparisonMode.HmacBased;
    private StringOperationMode _stringOperations = StringOperationMode.SecureEnclave;
    private MemoryProtection _memory = MemoryProtection.PinnedLocked;
    private KeyRotationPolicy _keyRotation = KeyRotationPolicy.EveryNOperations(1000);
    private AuditLevel _audit = AuditLevel.DecryptionsAndTransfers;
    private TaintMode _taint = TaintMode.Standard;
    private int _maxDecryptionCount = 100;
    private bool _autoDestroy;
    private bool _allowDemotion;
    private int? _decryptionRateLimit;
    private KeyStoreCapability _keyStoreMinimumCapability = KeyStoreCapability.InMemoryOnly;
    private OverflowMode _overflow = OverflowMode.Unchecked;

    /// <summary>Sets the display name of the policy.</summary>
    public SecurityPolicyBuilder WithName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        _name = name;
        return this;
    }

    /// <summary>Sets the arithmetic computation mode.</summary>
    public SecurityPolicyBuilder WithArithmeticMode(ArithmeticMode mode) { _arithmetic = mode; return this; }

    /// <summary>Sets the comparison mode for encrypted values.</summary>
    public SecurityPolicyBuilder WithComparisonMode(ComparisonMode mode) { _comparison = mode; return this; }

    /// <summary>Sets the string operation mode for encrypted strings.</summary>
    public SecurityPolicyBuilder WithStringOperationMode(StringOperationMode mode) { _stringOperations = mode; return this; }

    /// <summary>Sets the memory protection level for encrypted data buffers.</summary>
    public SecurityPolicyBuilder WithMemoryProtection(MemoryProtection mode) { _memory = mode; return this; }

    /// <summary>Sets the key rotation policy.</summary>
    public SecurityPolicyBuilder WithKeyRotation(KeyRotationPolicy policy) { _keyRotation = policy ?? throw new ArgumentNullException(nameof(policy)); return this; }

    /// <summary>Sets the audit logging verbosity level.</summary>
    public SecurityPolicyBuilder WithAuditLevel(AuditLevel level) { _audit = level; return this; }

    /// <summary>Sets the taint propagation mode.</summary>
    public SecurityPolicyBuilder WithTaintMode(TaintMode mode) { _taint = mode; return this; }

    /// <summary>Sets whether the encrypted value is automatically destroyed after reaching the decryption limit.</summary>
    public SecurityPolicyBuilder WithAutoDestroy(bool enabled) { _autoDestroy = enabled; return this; }

    /// <summary>Sets whether the policy allows demotion to a less restrictive policy.</summary>
    public SecurityPolicyBuilder WithAllowDemotion(bool enabled) { _allowDemotion = enabled; return this; }

    /// <summary>Sets the integer arithmetic overflow mode.</summary>
    public SecurityPolicyBuilder WithOverflowMode(OverflowMode mode) { _overflow = mode; return this; }

    /// <summary>Sets the maximum number of times the value may be decrypted.</summary>
    public SecurityPolicyBuilder WithMaxDecryptionCount(int count)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(count, 0);
        _maxDecryptionCount = count;
        return this;
    }

    /// <summary>Sets the maximum number of decryptions allowed per second.</summary>
    public SecurityPolicyBuilder WithDecryptionRateLimit(int maxPerSecond)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxPerSecond, 0);
        _decryptionRateLimit = maxPerSecond;
        return this;
    }

    /// <summary>Sets the minimum required key store capability level.</summary>
    public SecurityPolicyBuilder WithKeyStoreMinimumCapability(KeyStoreCapability capability)
    {
        _keyStoreMinimumCapability = capability;
        return this;
    }

    /// <summary>Validates the configuration and builds a <see cref="SecurityPolicy"/> instance.</summary>
    public SecurityPolicy Build()
    {
        Validate();
        return new SecurityPolicy(
            _name, _arithmetic, _comparison, _stringOperations,
            _memory, _keyRotation, _audit, _taint, _maxDecryptionCount,
            _autoDestroy, _allowDemotion, _decryptionRateLimit, _keyStoreMinimumCapability,
            _overflow);
    }

    private void Validate()
    {
        // HomomorphicCircuit comparison requires an FHE arithmetic mode
        if (_comparison == ComparisonMode.HomomorphicCircuit &&
            _arithmetic is not (ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull))
        {
            throw new PolicyViolationException(
                "ComparisonMode.HomomorphicCircuit requires ArithmeticMode.HomomorphicBasic or HomomorphicFull.");
        }

        // HomomorphicEquality string ops require at least PinnedLocked memory protection
        if (_stringOperations == StringOperationMode.HomomorphicEquality &&
            _memory > MemoryProtection.PinnedLocked)
        {
            throw new PolicyViolationException(
                "StringOperationMode.HomomorphicEquality requires at least PinnedLocked memory protection.");
        }

        // FHE arithmetic modes require at least PinnedLocked memory protection
        if (_arithmetic is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull &&
            _memory > MemoryProtection.PinnedLocked)
        {
            throw new PolicyViolationException(
                $"ArithmeticMode.{_arithmetic} requires at least PinnedLocked memory protection.");
        }

        // HomomorphicFull requires AllOperations audit level
        if (_arithmetic == ArithmeticMode.HomomorphicFull &&
            _audit != AuditLevel.AllOperations)
        {
            throw new PolicyViolationException(
                "HomomorphicFull arithmetic requires AuditLevel.AllOperations.");
        }

        // Strict taint requires at least DecryptionsAndTransfers audit
        if (_taint == TaintMode.Strict && _audit is AuditLevel.CompromiseOnly or AuditLevel.None)
        {
            throw new PolicyViolationException(
                "Strict taint mode requires at least DecryptionsAndTransfers audit level.");
        }

        // PinnedLockedReEncrypting requires a non-manual key rotation
        if (_memory == MemoryProtection.PinnedLockedReEncrypting &&
            _keyRotation.Kind == KeyRotationKind.Manual)
        {
            throw new PolicyViolationException(
                "PinnedLockedReEncrypting memory protection requires automatic key rotation.");
        }
    }
}
