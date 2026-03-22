using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Integration;

/// <summary>
/// End-to-end tests verifying the full FHE integration path:
/// SecurityPolicyBuilder → CyInt operators → FheEngineProvider → SealBfvEngine.
/// </summary>
[Collection("FHE")]
public sealed class FheIntegrationTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealBfvEngine _engine;
    private readonly SecurityPolicy _fhePolicy;

    public FheIntegrationTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _engine = new SealBfvEngine(_keyManager);
        FheEngineProvider.Configure(_engine);

        _fhePolicy = new SecurityPolicyBuilder()
            .WithName("FheIntegration")
            .WithArithmeticMode(ArithmeticMode.HomomorphicBasic)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .Build();
    }

    [Fact]
    public void CyInt_Add_via_FHE_produces_correct_result()
    {
        var encA = _engine.Encrypt(42);
        var encB = _engine.Encrypt(17);

        using var a = new CyInt(encA, _fhePolicy);
        using var b = new CyInt(encB, _fhePolicy);

        using var result = a + b;

        var decrypted = _engine.Decrypt(result.GetEncryptedBytes());
        decrypted.Should().Be(59);
    }

    [Fact]
    public void CyInt_Subtract_via_FHE_produces_correct_result()
    {
        var encA = _engine.Encrypt(100);
        var encB = _engine.Encrypt(37);

        using var a = new CyInt(encA, _fhePolicy);
        using var b = new CyInt(encB, _fhePolicy);

        using var result = a - b;

        var decrypted = _engine.Decrypt(result.GetEncryptedBytes());
        decrypted.Should().Be(63);
    }

    [Fact]
    public void CyInt_Multiply_via_FHE_produces_correct_result()
    {
        var encA = _engine.Encrypt(6);
        var encB = _engine.Encrypt(7);

        using var a = new CyInt(encA, _fhePolicy);
        using var b = new CyInt(encB, _fhePolicy);

        using var result = a * b;

        var decrypted = _engine.Decrypt(result.GetEncryptedBytes());
        decrypted.Should().Be(42);
    }

    [Fact]
    public void CyInt_SupportsFhe_returns_true_with_HomomorphicBasic_policy()
    {
        var enc = _engine.Encrypt(1);
        using var cy = new CyInt(enc, _fhePolicy);
        cy.SupportsFhe.Should().BeTrue();
    }

    [Fact]
    public void CyInt_FHE_result_preserves_policy()
    {
        var encA = _engine.Encrypt(10);
        var encB = _engine.Encrypt(20);

        using var a = new CyInt(encA, _fhePolicy);
        using var b = new CyInt(encB, _fhePolicy);

        using var result = a + b;

        result.Policy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicBasic);
    }

    [Fact]
    public void CyInt_FHE_chained_operations_produce_correct_result()
    {
        var enc1 = _engine.Encrypt(10);
        var enc2 = _engine.Encrypt(20);
        var enc3 = _engine.Encrypt(5);

        using var a = new CyInt(enc1, _fhePolicy);
        using var b = new CyInt(enc2, _fhePolicy);
        using var c = new CyInt(enc3, _fhePolicy);

        using var sum = a + b;      // 30
        using var result = sum * c; // 150

        var decrypted = _engine.Decrypt(result.GetEncryptedBytes());
        decrypted.Should().Be(150);
    }

    [Fact]
    public void HomomorphicFull_policy_builds_with_AllOperations_audit()
    {
        var fullPolicy = new SecurityPolicyBuilder()
            .WithName("FheFull")
            .WithArithmeticMode(ArithmeticMode.HomomorphicFull)
            .WithMemoryProtection(MemoryProtection.PinnedLocked)
            .WithAuditLevel(AuditLevel.AllOperations)
            .Build();

        fullPolicy.Arithmetic.Should().Be(ArithmeticMode.HomomorphicFull);

        var enc = _engine.Encrypt(42);
        using var cy = new CyInt(enc, fullPolicy);
        cy.SupportsFhe.Should().BeTrue();
    }

    public void Dispose()
    {
        FheEngineProvider.Reset();
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
