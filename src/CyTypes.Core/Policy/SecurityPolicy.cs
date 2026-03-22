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

    /// <summary>Gets the plaintext chunk size for stream encryption in bytes.</summary>
    public int StreamChunkSize { get; }

    /// <summary>Gets whether key exchange is required for IPC/network streams.</summary>
    public bool RequireKeyExchange { get; }

    /// <summary>Gets the stream integrity verification mode.</summary>
    public StreamIntegrityMode StreamIntegrity { get; }

    /// <summary>Gets the formatting mode controlling whether IFormattable exposes plaintext.</summary>
    public FormattingMode Formatting { get; }

    /// <summary>Gets the character access mode controlling CyString indexer behavior.</summary>
    public CharAccessMode CharAccess { get; }

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
        OverflowMode overflow = OverflowMode.Unchecked,
        int streamChunkSize = 65536,
        bool requireKeyExchange = true,
        StreamIntegrityMode streamIntegrity = StreamIntegrityMode.PerChunkPlusFooter,
        FormattingMode formatting = FormattingMode.Redacted,
        CharAccessMode charAccess = CharAccessMode.CompromiseOnAccess)
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
        StreamChunkSize = streamChunkSize;
        RequireKeyExchange = requireKeyExchange;
        StreamIntegrity = streamIntegrity;
        Formatting = formatting;
        CharAccess = charAccess;
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
        overflow: OverflowMode.Checked,
        streamChunkSize: 4096,
        requireKeyExchange: true,
        streamIntegrity: StreamIntegrityMode.PerChunkPlusFooter);

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
        allowDemotion: false,
        streamChunkSize: 65536,
        requireKeyExchange: true,
        streamIntegrity: StreamIntegrityMode.PerChunkPlusFooter);

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
        allowDemotion: false,
        streamChunkSize: 262144,
        requireKeyExchange: false,
        streamIntegrity: StreamIntegrityMode.PerChunkOnly);

    /// <summary>
    /// Homomorphic basic policy. Enables FHE arithmetic (add, subtract, multiply) on integer
    /// and floating-point types. Requires PinnedLocked memory and standard taint propagation.
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

    /// <summary>
    /// Homomorphic full policy. Enables FHE arithmetic, homomorphic comparisons,
    /// and deterministic string equality. Requires AllOperations audit level.
    /// </summary>
    public static SecurityPolicy HomomorphicFull { get; } = new(
        name: "HomomorphicFull",
        arithmetic: ArithmeticMode.HomomorphicFull,
        comparison: ComparisonMode.HomomorphicCircuit,
        stringOperations: StringOperationMode.HomomorphicEquality,
        memory: MemoryProtection.PinnedLocked,
        keyRotation: KeyRotationPolicy.EveryNOperations(1000),
        audit: AuditLevel.AllOperations,
        taint: TaintMode.Standard,
        maxDecryptionCount: 1000,
        autoDestroy: false,
        allowDemotion: false);

    /// <summary>Gets the default security policy, which is <see cref="Balanced"/>.</summary>
    public static SecurityPolicy Default => Balanced;

    /// <summary>Returns the policy name.</summary>
    public override string ToString() => Name;
}
