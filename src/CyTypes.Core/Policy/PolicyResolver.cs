using System.Globalization;
using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy.Components;

namespace CyTypes.Core.Policy;

/// <summary>
/// Resolves a combined policy when two CyType instances with different policies interact.
/// Implements 5 cross-policy resolution rules:
/// 1. Security level: always pick the higher (more secure) of each component.
/// 2. Taint propagation: stricter taint mode wins.
/// 3. Audit level: more verbose audit level wins.
/// 4. Key rotation: more frequent rotation wins.
/// 5. Memory protection: stronger protection wins.
/// </summary>
public static class PolicyResolver
{
    /// <summary>
    /// Resolves two security policies into a single combined policy by picking the most restrictive setting for each component.
    /// </summary>
    public static SecurityPolicy Resolve(SecurityPolicy left, SecurityPolicy right, bool allowStrictCrossPolicy = false)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        if (ReferenceEquals(left, right))
            return left;

        var arithmetic = PickHigher(left.Arithmetic, right.Arithmetic);
        var comparison = PickHigher(left.Comparison, right.Comparison);
        var stringOps = PickHigher(left.StringOperations, right.StringOperations);
        var memory = PickHigher(left.Memory, right.Memory);
        var taint = PickStricter(left.Taint, right.Taint);
        var audit = PickMoreVerbose(left.Audit, right.Audit);
        var keyRotation = PickMoreFrequent(left.KeyRotation, right.KeyRotation);
        var maxDecrypt = Math.Min(left.MaxDecryptionCount, right.MaxDecryptionCount);

        // Rule 2: If either operand has TaintMode.Strict and policies differ,
        // cross-policy interaction requires explicit opt-in
        if (!allowStrictCrossPolicy &&
            (left.Taint == TaintMode.Strict || right.Taint == TaintMode.Strict) &&
            !ReferenceEquals(left, right))
        {
            throw new PolicyViolationException(
                "Cross-policy interaction with TaintMode.Strict requires explicit cast. " +
                $"Policies: {left.Name} and {right.Name}.");
        }

        // AllowDemotion: use more permissive value (if either allows, it's allowed in resolved)
        var allowDemotion = left.AllowDemotion || right.AllowDemotion;
        // AutoDestroy: use more restrictive value (if either requires, it's required in resolved)
        var autoDestroy = left.AutoDestroy || right.AutoDestroy;
        // DecryptionRateLimit: use more restrictive (lower) value
        var rateLimit = PickMoreRestrictiveRateLimit(left.DecryptionRateLimit, right.DecryptionRateLimit);
        // KeyStoreMinimumCapability: use more restrictive (lower ordinal = stronger)
        var keyStoreCap = (KeyStoreCapability)Math.Min((int)left.KeyStoreMinimumCapability, (int)right.KeyStoreMinimumCapability);
        // OverflowMode: use safer (Checked wins over Unchecked)
        var overflow = (OverflowMode)Math.Min((int)left.Overflow, (int)right.Overflow);
        // FormattingMode: more restrictive (Redacted) wins
        var formatting = (FormattingMode)Math.Min((int)left.Formatting, (int)right.Formatting);
        var charAccess = (CharAccessMode)Math.Min((int)left.CharAccess, (int)right.CharAccess);

        return new SecurityPolicy(
            name: $"Resolved({left.Name}+{right.Name})",
            arithmetic: arithmetic,
            comparison: comparison,
            stringOperations: stringOps,
            memory: memory,
            keyRotation: keyRotation,
            audit: audit,
            taint: taint,
            maxDecryptionCount: maxDecrypt,
            autoDestroy: autoDestroy,
            allowDemotion: allowDemotion,
            decryptionRateLimit: rateLimit,
            keyStoreMinimumCapability: keyStoreCap,
            overflow: overflow,
            formatting: formatting,
            charAccess: charAccess);
    }

    /// <summary>
    /// Resolves two policies and returns a detailed explanation of how each component was resolved.
    /// Useful for diagnostics and debugging policy interactions.
    /// </summary>
    public static PolicyResolutionExplanation Explain(SecurityPolicy left, SecurityPolicy right, bool allowStrictCrossPolicy = false)
    {
        var resolved = Resolve(left, right, allowStrictCrossPolicy);
        var components = new List<ComponentResolution>
        {
            new("Arithmetic", left.Arithmetic.ToString(), right.Arithmetic.ToString(),
                resolved.Arithmetic.ToString(), "Higher security (lower ordinal) wins"),
            new("Comparison", left.Comparison.ToString(), right.Comparison.ToString(),
                resolved.Comparison.ToString(), "Higher security (lower ordinal) wins"),
            new("StringOperations", left.StringOperations.ToString(), right.StringOperations.ToString(),
                resolved.StringOperations.ToString(), "Higher security (lower ordinal) wins"),
            new("Memory", left.Memory.ToString(), right.Memory.ToString(),
                resolved.Memory.ToString(), "Stronger protection (lower ordinal) wins"),
            new("Taint", left.Taint.ToString(), right.Taint.ToString(),
                resolved.Taint.ToString(), "Stricter taint mode wins"),
            new("Audit", left.Audit.ToString(), right.Audit.ToString(),
                resolved.Audit.ToString(), "More verbose audit level wins"),
            new("KeyRotation", left.KeyRotation.ToString(), right.KeyRotation.ToString(),
                resolved.KeyRotation.ToString(), "More frequent rotation wins"),
            new("MaxDecryptionCount", left.MaxDecryptionCount.ToString(CultureInfo.InvariantCulture), right.MaxDecryptionCount.ToString(CultureInfo.InvariantCulture),
                resolved.MaxDecryptionCount.ToString(CultureInfo.InvariantCulture), "Lower (more restrictive) count wins"),
            new("AutoDestroy", left.AutoDestroy.ToString(), right.AutoDestroy.ToString(),
                resolved.AutoDestroy.ToString(), "True (more restrictive) wins if either is true"),
            new("AllowDemotion", left.AllowDemotion.ToString(), right.AllowDemotion.ToString(),
                resolved.AllowDemotion.ToString(), "True (more permissive) wins if either allows"),
            new("DecryptionRateLimit",
                left.DecryptionRateLimit?.ToString(CultureInfo.InvariantCulture) ?? "unlimited",
                right.DecryptionRateLimit?.ToString(CultureInfo.InvariantCulture) ?? "unlimited",
                resolved.DecryptionRateLimit?.ToString(CultureInfo.InvariantCulture) ?? "unlimited",
                "Lower (more restrictive) limit wins"),
            new("Overflow", left.Overflow.ToString(), right.Overflow.ToString(),
                resolved.Overflow.ToString(), "Checked (safer) wins over Unchecked"),
        };

        return new PolicyResolutionExplanation(resolved.Name, components);
    }

    // Rule 1: Higher security = lower enum ordinal (HomomorphicFull < HomomorphicBasic < SecureEnclave)
    private static ArithmeticMode PickHigher(ArithmeticMode a, ArithmeticMode b) =>
        (ArithmeticMode)Math.Min((int)a, (int)b);

    private static ComparisonMode PickHigher(ComparisonMode a, ComparisonMode b) =>
        (ComparisonMode)Math.Min((int)a, (int)b);

    private static StringOperationMode PickHigher(StringOperationMode a, StringOperationMode b) =>
        (StringOperationMode)Math.Min((int)a, (int)b);

    // Rule 5: Stronger memory = lower ordinal
    private static MemoryProtection PickHigher(MemoryProtection a, MemoryProtection b) =>
        (MemoryProtection)Math.Min((int)a, (int)b);

    // Rule 2: Stricter taint = lower ordinal (Strict < Standard < Relaxed)
    private static TaintMode PickStricter(TaintMode a, TaintMode b) =>
        (TaintMode)Math.Min((int)a, (int)b);

    // Rule 3: More verbose audit = lower ordinal (AllOperations < DecryptionsAndTransfers < CompromiseOnly < None)
    private static AuditLevel PickMoreVerbose(AuditLevel a, AuditLevel b) =>
        (AuditLevel)Math.Min((int)a, (int)b);

    // Rule 4: More frequent key rotation wins
    private static KeyRotationPolicy PickMoreFrequent(KeyRotationPolicy a, KeyRotationPolicy b)
    {
        // Manual is least frequent — any automatic policy wins
        if (a.Kind == KeyRotationKind.Manual) return b;
        if (b.Kind == KeyRotationKind.Manual) return a;

        // Both are automatic; normalize to approximate operations-per-rotation
        // For time-based, treat 1 minute ≈ 10 operations for comparison
        var aEffective = EffectiveOperations(a);
        var bEffective = EffectiveOperations(b);

        return aEffective <= bEffective ? a : b;
    }

    private static int EffectiveOperations(KeyRotationPolicy p) => p.Kind switch
    {
        KeyRotationKind.EveryNOperations => p.Value,
        KeyRotationKind.EveryNMinutes => p.Value * 10,
        _ => int.MaxValue
    };

    private static int? PickMoreRestrictiveRateLimit(int? a, int? b) => (a, b) switch
    {
        (null, null) => null,
        (not null, null) => a,
        (null, not null) => b,
        _ => Math.Min(a!.Value, b!.Value)
    };
}
