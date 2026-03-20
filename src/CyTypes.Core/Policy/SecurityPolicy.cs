using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Policy;

/// <summary>
/// Immutable security policy that governs how CyType instances protect, audit, and manage encrypted data.
/// </summary>
public sealed class SecurityPolicy
{
    /// <summary>Gets the display name of this policy.</summary>
    public string Name { get; }

    /// <summary>Gets the arithmetic computation mode.</summary>
    public ArithmeticMode Arithmetic { get; }

    /// <summary>Gets the comparison mode for encrypted values.</summary>
    public ComparisonMode Comparison { get; }

    /// <summary>Gets the string operation mode for encrypted strings.</summary>
    public StringOperationMode StringOperations { get; }

    /// <summary>Gets the memory protection level for encrypted data buffers.</summary>
    public MemoryProtection Memory { get; }

    /// <summary>Gets the key rotation policy.</summary>
    public KeyRotationPolicy KeyRotation { get; }

    /// <summary>Gets the audit logging verbosity level.</summary>
    public AuditLevel Audit { get; }

    /// <summary>Gets the taint propagation mode.</summary>
    public TaintMode Taint { get; }

    /// <summary>Gets the maximum number of times the value may be decrypted.</summary>
    public int MaxDecryptionCount { get; }

    /// <summary>Gets a value indicating whether the encrypted value is automatically destroyed after reaching the decryption limit.</summary>
    public bool AutoDestroy { get; }

    /// <summary>Gets a value indicating whether the policy allows demotion to a less restrictive policy.</summary>
    public bool AllowDemotion { get; }

    /// <summary>Gets the maximum number of decryptions allowed per second, or <c>null</c> if unlimited.</summary>
    public int? DecryptionRateLimit { get; }

    /// <summary>Gets the minimum required key store capability level.</summary>
    public KeyStoreCapability KeyStoreMinimumCapability { get; }

    /// <summary>Gets the integer arithmetic overflow mode.</summary>
    public OverflowMode Overflow { get; }

    internal SecurityPolicy(
        string name,
        ArithmeticMode arithmetic,
        ComparisonMode comparison,
        StringOperationMode stringOperations,
        MemoryProtection memory,
        KeyRotationPolicy keyRotation,
        AuditLevel audit,
        TaintMode taint,
        int maxDecryptionCount,
        bool autoDestroy,
        bool allowDemotion,
        int? decryptionRateLimit = null,
        KeyStoreCapability keyStoreMinimumCapability = KeyStoreCapability.InMemoryOnly,
        OverflowMode overflow = OverflowMode.Unchecked)
    {
        Name = name;
        Arithmetic = arithmetic;
        Comparison = comparison;
        StringOperations = stringOperations;
        Memory = memory;
        KeyRotation = keyRotation;
        Audit = audit;
        Taint = taint;
        MaxDecryptionCount = maxDecryptionCount;
        AutoDestroy = autoDestroy;
        AllowDemotion = allowDemotion;
        DecryptionRateLimit = decryptionRateLimit;
        KeyStoreMinimumCapability = keyStoreMinimumCapability;
        Overflow = overflow;
    }

    /// <summary>
    /// Maximum security policy. Uses SecureEnclave arithmetic (FHE modes reserved for Phase 3),
    /// HMAC-based comparison, strict taint, and checked integer arithmetic.
    /// </summary>
    public static SecurityPolicy Maximum { get; } = new(
        name: "Maximum",
        arithmetic: ArithmeticMode.SecureEnclave,
        comparison: ComparisonMode.HmacBased,
        stringOperations: StringOperationMode.SecureEnclave,
        memory: MemoryProtection.PinnedLockedReEncrypting,
        keyRotation: KeyRotationPolicy.EveryNOperations(100),
        audit: AuditLevel.AllOperations,
        taint: TaintMode.Strict,
        maxDecryptionCount: 10,
        autoDestroy: true,
        allowDemotion: false,
        decryptionRateLimit: 10,
        keyStoreMinimumCapability: KeyStoreCapability.OsProtected,
        overflow: OverflowMode.Checked);

    /// <summary>
    /// Balanced policy (default). SecureEnclave arithmetic, HMAC comparison, standard taint.
    /// </summary>
    public static SecurityPolicy Balanced { get; } = new(
        name: "Balanced",
        arithmetic: ArithmeticMode.SecureEnclave,
        comparison: ComparisonMode.HmacBased,
        stringOperations: StringOperationMode.SecureEnclave,
        memory: MemoryProtection.PinnedLocked,
        keyRotation: KeyRotationPolicy.EveryNOperations(1000),
        audit: AuditLevel.DecryptionsAndTransfers,
        taint: TaintMode.Standard,
        maxDecryptionCount: 100,
        autoDestroy: false,
        allowDemotion: false);

    /// <summary>
    /// Performance policy. Minimal overhead, unchecked arithmetic, relaxed taint.
    /// </summary>
    public static SecurityPolicy Performance { get; } = new(
        name: "Performance",
        arithmetic: ArithmeticMode.SecureEnclave,
        comparison: ComparisonMode.SecureEnclave,
        stringOperations: StringOperationMode.SecureEnclave,
        memory: MemoryProtection.PinnedOnly,
        keyRotation: KeyRotationPolicy.Manual,
        audit: AuditLevel.CompromiseOnly,
        taint: TaintMode.Relaxed,
        maxDecryptionCount: int.MaxValue,
        autoDestroy: false,
        allowDemotion: false);

    /// <summary>
    /// Homomorphic basic policy. Enables FHE arithmetic (add, subtract, multiply) on integer types.
    /// Requires PinnedLocked memory and standard taint propagation.
    /// </summary>
    public static SecurityPolicy HomomorphicBasic { get; } = new(
        name: "HomomorphicBasic",
        arithmetic: ArithmeticMode.HomomorphicBasic,
        comparison: ComparisonMode.HmacBased,
        stringOperations: StringOperationMode.SecureEnclave,
        memory: MemoryProtection.PinnedLocked,
        keyRotation: KeyRotationPolicy.EveryNOperations(1000),
        audit: AuditLevel.DecryptionsAndTransfers,
        taint: TaintMode.Standard,
        maxDecryptionCount: 1000,
        autoDestroy: false,
        allowDemotion: false);

    /// <summary>Gets the default security policy, which is <see cref="Balanced"/>.</summary>
    public static SecurityPolicy Default => Balanced;

    /// <summary>Returns the policy name.</summary>
    public override string ToString() => Name;
}
