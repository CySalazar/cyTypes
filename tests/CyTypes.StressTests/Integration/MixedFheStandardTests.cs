using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Primitives.Shared;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Integration;

[Trait("Category", "Stress"), Trait("SubCategory", "Integration")]
public class MixedFheStandardTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly SealKeyManager _bfvKeyManager;
    private readonly SealBfvEngine _bfvEngine;
    private readonly SealKeyManager _ckksKeyManager;
    private readonly SealCkksEngine _ckksEngine;

    public MixedFheStandardTests(ITestOutputHelper output)
    {
        _output = output;
        _bfvKeyManager = new SealKeyManager();
        _bfvKeyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _bfvEngine = new SealBfvEngine(_bfvKeyManager);

        _ckksKeyManager = new SealKeyManager();
        _ckksKeyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
        _ckksEngine = new SealCkksEngine(_ckksKeyManager);

        // Register engines globally so CyType constructors with HomomorphicBasic policy can use them
        FheEngineProvider.Configure(_bfvEngine);
        FheEngineProvider.Configure(_ckksEngine);
    }

    [Fact]
    public void Standard_To_Fhe_To_Standard_Workflow()
    {
        // Step 1: encrypt with BFV via engine directly (standard → FHE)
        var ct1 = _bfvEngine.Encrypt(42);
        var ct2 = _bfvEngine.Encrypt(8);

        // Step 2: homomorphic addition
        var ctSum = _bfvEngine.Add(ct1, ct2);

        // Step 3: decrypt (FHE → standard)
        var result = _bfvEngine.Decrypt(ctSum);

        result.Should().Be(50, "42 + 8 = 50 via FHE");
        _output.WriteLine($"Standard→FHE→Standard workflow: 42 + 8 = {result}");
    }

    [Fact]
    public void Fhe_BulkAdd_ThenDecrypt_Correctness()
    {
        const int count = 100;
        var accumulator = _bfvEngine.Encrypt(0);

        for (var i = 1; i <= count; i++)
        {
            var ct = _bfvEngine.Encrypt(i);
            accumulator = _bfvEngine.Add(accumulator, ct);
        }

        var result = _bfvEngine.Decrypt(accumulator);
        var expected = count * (count + 1) / 2; // Sum of 1..100 = 5050

        result.Should().Be(expected, $"sum of 1..{count} should be {expected}");
        _output.WriteLine($"FHE bulk add: sum(1..{count}) = {result}");
    }

    [Fact]
    public void Fhe_Ckks_FloatingPoint_Pipeline()
    {
        var ct1 = _ckksEngine.Encrypt(3.14);
        var ct2 = _ckksEngine.Encrypt(2.0);

        var ctSum = _ckksEngine.Add(ct1, ct2);
        var result = _ckksEngine.Decrypt(ctSum);

        result.Should().BeApproximately(5.14, 0.01, "CKKS addition of 3.14 + 2.0 should be ~5.14");
        _output.WriteLine($"CKKS float pipeline: 3.14 + 2.0 = {result:F4}");
    }

    public void Dispose()
    {
        FheEngineProvider.Reset();
        _bfvKeyManager.Dispose();
        _ckksKeyManager.Dispose();
        GC.SuppressFinalize(this);
    }
}
