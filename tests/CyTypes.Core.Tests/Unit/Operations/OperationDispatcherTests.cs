using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Operations;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Core.Security;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Operations;

public sealed class OperationDispatcherTests
{
    private readonly ICryptoEngine _engine = new AesGcmEngine();
    private readonly SecurityAuditor _auditor = new(NullLogger<SecurityAuditor>.Instance);

    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void Dispatches_add_via_SecureEnclave_when_both_policies_use_Performance()
    {
        var dispatcher = new OperationDispatcher(_engine, _auditor);
        var key = GenerateKey();

        var encA = _engine.Encrypt(BitConverter.GetBytes(5), key);
        var encB = _engine.Encrypt(BitConverter.GetBytes(3), key);

        var ctxA = new SecurityContext(Guid.NewGuid(), int.MaxValue);
        var ctxB = new SecurityContext(Guid.NewGuid(), int.MaxValue);

        var resultEnc = dispatcher.DispatchAdd<int>(
            encA, encB, key,
            SecurityPolicy.Performance, SecurityPolicy.Performance,
            ctxA, ctxB);

        var result = BitConverter.ToInt32(_engine.Decrypt(resultEnc, key));
        result.Should().Be(8);
    }

    [Fact]
    public void Dispatches_add_via_SecureEnclave_with_Maximum_policy()
    {
        var dispatcher = new OperationDispatcher(_engine, _auditor);
        var key = GenerateKey();

        var encA = _engine.Encrypt(BitConverter.GetBytes(5), key);
        var encB = _engine.Encrypt(BitConverter.GetBytes(3), key);

        var ctxA = new SecurityContext(Guid.NewGuid(), int.MaxValue);
        var ctxB = new SecurityContext(Guid.NewGuid(), int.MaxValue);

        // Maximum now uses SecureEnclave, so this should succeed
        var resultEnc = dispatcher.DispatchAdd<int>(
            encA, encB, key,
            SecurityPolicy.Maximum, SecurityPolicy.Maximum,
            ctxA, ctxB);

        var result = BitConverter.ToInt32(_engine.Decrypt(resultEnc, key));
        result.Should().Be(8);
    }

    [Fact]
    public void Uses_resolved_policy_when_policies_differ()
    {
        var dispatcher = new OperationDispatcher(_engine, _auditor);
        var key = GenerateKey();

        var encA = _engine.Encrypt(BitConverter.GetBytes(10), key);
        var encB = _engine.Encrypt(BitConverter.GetBytes(7), key);

        var ctxA = new SecurityContext(Guid.NewGuid(), int.MaxValue);
        var ctxB = new SecurityContext(Guid.NewGuid(), int.MaxValue);

        // Performance + Balanced both use SecureEnclave now — should succeed
        var resultEnc = dispatcher.DispatchAdd<int>(
            encA, encB, key,
            SecurityPolicy.Performance, SecurityPolicy.Balanced,
            ctxA, ctxB);

        var result = BitConverter.ToInt32(_engine.Decrypt(resultEnc, key));
        result.Should().Be(17);
    }

    [Fact]
    public void FHE_HomomorphicFull_without_engine_throws_InvalidOperationException()
    {
        var fhePolicy = new SecurityPolicy(
            name: "FheTest",
            arithmetic: ArithmeticMode.HomomorphicFull,
            comparison: ComparisonMode.SecureEnclave,
            stringOperations: StringOperationMode.SecureEnclave,
            memory: MemoryProtection.PinnedLocked,
            keyRotation: KeyRotationPolicy.EveryNOperations(100),
            audit: AuditLevel.AllOperations,
            taint: TaintMode.Relaxed,
            maxDecryptionCount: int.MaxValue,
            autoDestroy: false,
            allowDemotion: false);

        var dispatcher = new OperationDispatcher(_engine, _auditor);
        var key = GenerateKey();
        var encA = _engine.Encrypt(BitConverter.GetBytes(1), key);
        var encB = _engine.Encrypt(BitConverter.GetBytes(2), key);
        var ctxA = new SecurityContext(Guid.NewGuid(), int.MaxValue);
        var ctxB = new SecurityContext(Guid.NewGuid(), int.MaxValue);

        var act = () => dispatcher.DispatchMultiply<int>(
            encA, encB, key,
            fhePolicy, fhePolicy,
            ctxA, ctxB);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*FHE engine not configured*");
    }

    [Fact]
    public void FHE_HomomorphicBasic_without_engine_throws_InvalidOperationException()
    {
        var fhePolicy = new SecurityPolicy(
            name: "FheBasicTest",
            arithmetic: ArithmeticMode.HomomorphicBasic,
            comparison: ComparisonMode.SecureEnclave,
            stringOperations: StringOperationMode.SecureEnclave,
            memory: MemoryProtection.PinnedLocked,
            keyRotation: KeyRotationPolicy.EveryNOperations(100),
            audit: AuditLevel.AllOperations,
            taint: TaintMode.Relaxed,
            maxDecryptionCount: int.MaxValue,
            autoDestroy: false,
            allowDemotion: false);

        var dispatcher = new OperationDispatcher(_engine, _auditor);
        var key = GenerateKey();
        var encA = _engine.Encrypt(BitConverter.GetBytes(1), key);
        var encB = _engine.Encrypt(BitConverter.GetBytes(2), key);
        var ctxA = new SecurityContext(Guid.NewGuid(), int.MaxValue);
        var ctxB = new SecurityContext(Guid.NewGuid(), int.MaxValue);

        var act = () => dispatcher.DispatchSubtract<int>(
            encA, encB, key,
            fhePolicy, fhePolicy,
            ctxA, ctxB);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*FHE engine not configured*");
    }

    [Fact]
    public void FHE_Division_always_uses_SecureEnclave()
    {
        var fhePolicy = new SecurityPolicy(
            name: "FheBasicTest",
            arithmetic: ArithmeticMode.HomomorphicBasic,
            comparison: ComparisonMode.SecureEnclave,
            stringOperations: StringOperationMode.SecureEnclave,
            memory: MemoryProtection.PinnedLocked,
            keyRotation: KeyRotationPolicy.EveryNOperations(100),
            audit: AuditLevel.AllOperations,
            taint: TaintMode.Relaxed,
            maxDecryptionCount: int.MaxValue,
            autoDestroy: false,
            allowDemotion: false);

        var dispatcher = new OperationDispatcher(_engine, _auditor);
        var key = GenerateKey();
        var encA = _engine.Encrypt(BitConverter.GetBytes(10), key);
        var encB = _engine.Encrypt(BitConverter.GetBytes(2), key);
        var ctxA = new SecurityContext(Guid.NewGuid(), int.MaxValue);
        var ctxB = new SecurityContext(Guid.NewGuid(), int.MaxValue);

        // Division should work via SecureEnclave even with FHE policy
        var resultEnc = dispatcher.DispatchDivide<int>(
            encA, encB, key,
            fhePolicy, fhePolicy,
            ctxA, ctxB);

        var result = BitConverter.ToInt32(_engine.Decrypt(resultEnc, key));
        result.Should().Be(5);
    }
}
