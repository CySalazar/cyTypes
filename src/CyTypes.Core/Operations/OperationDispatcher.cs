using System.Numerics;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Core.Security;

namespace CyTypes.Core.Operations;

/// <summary>
/// Dispatches arithmetic and comparison operations on encrypted values, handling policy resolution, taint propagation, and audit recording.
/// Routes to FHE engine when policy requires homomorphic operations and engine is available.
/// </summary>
public sealed class OperationDispatcher
{
    private readonly SecureEnclaveExecutor _enclaveExecutor;
    private readonly SecurityAuditor _auditor;
    private readonly IFheEngine? _fheEngine;

    /// <summary>Initializes a new dispatcher with the specified crypto engine and security auditor.</summary>
    public OperationDispatcher(
        ICryptoEngine cryptoEngine,
        SecurityAuditor auditor,
        IFheEngine? fheEngine = null)
    {
        _enclaveExecutor = new SecureEnclaveExecutor(cryptoEngine);
        _auditor = auditor ?? throw new ArgumentNullException(nameof(auditor));
        _fheEngine = fheEngine;
    }

    /// <summary>Dispatches an addition operation on two encrypted operands with policy resolution and audit.</summary>
    public byte[] DispatchAdd<T>(
        byte[] encryptedA, byte[] encryptedB,
        ReadOnlySpan<byte> key,
        SecurityPolicy policyA, SecurityPolicy policyB,
        SecurityContext contextA, SecurityContext contextB)
        where T : INumber<T>
    {
        var resolved = ResolveAndPropagateTaint(policyA, policyB, contextA, contextB);

        if (IsFheMode(resolved.Arithmetic))
        {
            EnsureFheEngine();
            var result = _fheEngine!.Add(encryptedA, encryptedB);
            RecordOperation(contextA, resolved, "Add via FHE");
            RecordOperation(contextB, resolved, "Add via FHE");
            return result;
        }

        var enclaveResult = _enclaveExecutor.Add<T>(encryptedA, encryptedB, key);
        RecordOperation(contextA, resolved, "Add via SecureEnclave");
        RecordOperation(contextB, resolved, "Add via SecureEnclave");
        return enclaveResult;
    }

    /// <summary>Dispatches a subtraction operation on two encrypted operands with policy resolution and audit.</summary>
    public byte[] DispatchSubtract<T>(
        byte[] encryptedA, byte[] encryptedB,
        ReadOnlySpan<byte> key,
        SecurityPolicy policyA, SecurityPolicy policyB,
        SecurityContext contextA, SecurityContext contextB)
        where T : INumber<T>
    {
        var resolved = ResolveAndPropagateTaint(policyA, policyB, contextA, contextB);

        if (IsFheMode(resolved.Arithmetic))
        {
            EnsureFheEngine();
            var result = _fheEngine!.Subtract(encryptedA, encryptedB);
            RecordOperation(contextA, resolved, "Subtract via FHE");
            RecordOperation(contextB, resolved, "Subtract via FHE");
            return result;
        }

        var enclaveResult = _enclaveExecutor.Subtract<T>(encryptedA, encryptedB, key);
        RecordOperation(contextA, resolved, "Subtract via SecureEnclave");
        RecordOperation(contextB, resolved, "Subtract via SecureEnclave");
        return enclaveResult;
    }

    /// <summary>Dispatches a multiplication operation on two encrypted operands with policy resolution and audit.</summary>
    public byte[] DispatchMultiply<T>(
        byte[] encryptedA, byte[] encryptedB,
        ReadOnlySpan<byte> key,
        SecurityPolicy policyA, SecurityPolicy policyB,
        SecurityContext contextA, SecurityContext contextB)
        where T : INumber<T>
    {
        var resolved = ResolveAndPropagateTaint(policyA, policyB, contextA, contextB);

        if (IsFheMode(resolved.Arithmetic))
        {
            EnsureFheEngine();
            var result = _fheEngine!.Multiply(encryptedA, encryptedB);
            RecordOperation(contextA, resolved, "Multiply via FHE");
            RecordOperation(contextB, resolved, "Multiply via FHE");
            return result;
        }

        var enclaveResult = _enclaveExecutor.Multiply<T>(encryptedA, encryptedB, key);
        RecordOperation(contextA, resolved, "Multiply via SecureEnclave");
        RecordOperation(contextB, resolved, "Multiply via SecureEnclave");
        return enclaveResult;
    }

    /// <summary>Dispatches a division operation on two encrypted operands with policy resolution and audit.</summary>
    public byte[] DispatchDivide<T>(
        byte[] encryptedA, byte[] encryptedB,
        ReadOnlySpan<byte> key,
        SecurityPolicy policyA, SecurityPolicy policyB,
        SecurityContext contextA, SecurityContext contextB)
        where T : INumber<T>
    {
        // Division always uses SecureEnclave (not FHE-supported for integers)
        var resolved = ResolveAndPropagateTaint(policyA, policyB, contextA, contextB);
        var result = _enclaveExecutor.Divide<T>(encryptedA, encryptedB, key);
        RecordOperation(contextA, resolved, "Divide via SecureEnclave");
        RecordOperation(contextB, resolved, "Divide via SecureEnclave");
        return result;
    }

    /// <summary>Dispatches a modulo operation on two encrypted operands with policy resolution and audit.</summary>
    public byte[] DispatchModulo<T>(
        byte[] encryptedA, byte[] encryptedB,
        ReadOnlySpan<byte> key,
        SecurityPolicy policyA, SecurityPolicy policyB,
        SecurityContext contextA, SecurityContext contextB)
        where T : INumber<T>, IModulusOperators<T, T, T>
    {
        // Modulo always uses SecureEnclave (not FHE-supported)
        var resolved = ResolveAndPropagateTaint(policyA, policyB, contextA, contextB);
        var result = _enclaveExecutor.Modulo<T>(encryptedA, encryptedB, key);
        RecordOperation(contextA, resolved, "Modulo via SecureEnclave");
        RecordOperation(contextB, resolved, "Modulo via SecureEnclave");
        return result;
    }

    /// <summary>Dispatches an equality comparison on two encrypted operands with policy resolution and audit.</summary>
    public bool DispatchCompare<T>(
        byte[] encryptedA, byte[] encryptedB,
        ReadOnlySpan<byte> key,
        SecurityPolicy policyA, SecurityPolicy policyB,
        SecurityContext contextA, SecurityContext contextB)
        where T : INumber<T>, IComparisonOperators<T, T, bool>
    {
        var resolved = ResolveAndPropagateTaint(policyA, policyB, contextA, contextB);
        var result = _enclaveExecutor.Compare<T>(encryptedA, encryptedB, key);
        RecordOperation(contextA, resolved, "Compare via SecureEnclave");
        RecordOperation(contextB, resolved, "Compare via SecureEnclave");
        return result;
    }

    /// <summary>
    /// Resolves policy and propagates taint: if either context is compromised or tainted,
    /// both contexts are marked tainted (taint propagation per spec).
    /// </summary>
    private static SecurityPolicy ResolveAndPropagateTaint(
        SecurityPolicy policyA, SecurityPolicy policyB,
        SecurityContext contextA, SecurityContext contextB)
    {
        // SECURITY: Taint propagation — if either operand is compromised or tainted,
        // the operation result inherits taint
        if (contextA.IsCompromised || contextA.IsTainted || contextB.IsCompromised || contextB.IsTainted)
        {
            contextA.MarkTainted();
            contextB.MarkTainted();
        }

        // For cross-policy resolution, use allowStrictCrossPolicy since the dispatcher
        // is an internal operation path (the caller already made the explicit decision)
        return PolicyResolver.Resolve(policyA, policyB, allowStrictCrossPolicy: true);
    }

    private static bool IsFheMode(ArithmeticMode mode) =>
        mode is ArithmeticMode.HomomorphicBasic or ArithmeticMode.HomomorphicFull;

    private void EnsureFheEngine()
    {
        if (_fheEngine == null)
            throw new InvalidOperationException(
                "FHE engine not configured. Register via AddCyTypesFhe().");
    }

    private void RecordOperation(SecurityContext context, SecurityPolicy policy, string description)
    {
        context.IncrementOperation();
        _auditor.RecordEvent(
            new SecurityEvent(
                DateTime.UtcNow,
                SecurityEventType.OperationPerformed,
                context.InstanceId,
                description,
                policy.Name),
            policy.Audit);
    }
}
