using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.StressTests.Infrastructure;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Throughput;

[Trait("Category", "Stress"), Trait("SubCategory", "Throughput")]
public class FheThroughputTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly SealKeyManager _bfvKeyManager;
    private readonly SealBfvEngine _bfvEngine;
    private readonly SealKeyManager _ckksKeyManager;
    private readonly SealCkksEngine _ckksEngine;

    public FheThroughputTests(ITestOutputHelper output)
    {
        _output = output;
        _bfvKeyManager = new SealKeyManager();
        _bfvKeyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _bfvEngine = new SealBfvEngine(_bfvKeyManager);

        _ckksKeyManager = new SealKeyManager();
        _ckksKeyManager.Initialize(FheScheme.CKKS, SealParameterPresets.Ckks128Bit());
        _ckksEngine = new SealCkksEngine(_ckksKeyManager);
    }

    [Fact]
    public void BfvEngine_Add_Chain_UntilNoiseExhaustion()
    {
        var counter = new ThroughputCounter();
        var a = _bfvEngine.Encrypt(1);
        var accumulator = _bfvEngine.Encrypt(0);
        var lastBudget = _bfvEngine.GetNoiseBudget(accumulator);

        var operations = 0;
        try
        {
            for (var i = 0; i < 10_000; i++)
            {
                accumulator = _bfvEngine.Add(accumulator, a);
                counter.Increment();
                operations++;

                var budget = _bfvEngine.GetNoiseBudget(accumulator);
                if (budget <= 0)
                {
                    _output.WriteLine($"Noise exhausted after {operations} additions (budget: {budget})");
                    break;
                }
                lastBudget = budget;
            }
        }
        catch (Exception ex)
        {
            _output.WriteLine($"Exception after {operations} additions: {ex.GetType().Name}");
        }

        operations.Should().BeGreaterThan(0, "at least some FHE additions should succeed");

        // Verify correctness by decrypting
        var result = _bfvEngine.Decrypt(accumulator);
        result.Should().Be(operations, $"adding 1 {operations} times should give {operations}");

        _output.WriteLine($"BFV Add chain: {counter.Summary}, noise budget remaining: {lastBudget}");
    }

    [Fact]
    public void CkksEngine_Multiply_Chain_Throughput()
    {
        var counter = new ThroughputCounter();
        var accumulator = _ckksEngine.Encrypt(2.0);
        var factor = _ckksEngine.Encrypt(1.001);

        var operations = 0;
        var lastBudget = _ckksEngine.GetNoiseBudget(accumulator);

        for (var i = 0; i < 5; i++)
        {
            try
            {
                accumulator = _ckksEngine.Multiply(accumulator, factor);
                counter.Increment();
                operations++;

                var budget = _ckksEngine.GetNoiseBudget(accumulator);
                _output.WriteLine($"  Multiply {i + 1}: budget={budget}");

                if (budget <= 0) break;
                lastBudget = budget;
            }
            catch (Exception ex)
            {
                _output.WriteLine($"Exception after {operations} multiplies: {ex.GetType().Name}: {ex.Message}");
                break;
            }
        }

        operations.Should().BeGreaterThan(0, "at least some CKKS multiplications should succeed");
        _output.WriteLine($"CKKS Multiply chain: {counter.Summary}, final budget: {lastBudget}");
    }

    [Fact]
    public void MixedOps_BfvEngine_AddMultiply_Throughput()
    {
        var counter = new ThroughputCounter();
        var a = _bfvEngine.Encrypt(3);
        var b = _bfvEngine.Encrypt(4);

        // Interleave add and multiply
        var result = _bfvEngine.Add(a, b); // 3 + 4 = 7
        counter.Increment();

        var c = _bfvEngine.Encrypt(2);
        result = _bfvEngine.Multiply(result, c); // 7 * 2 = 14
        counter.Increment();

        var d = _bfvEngine.Encrypt(6);
        result = _bfvEngine.Add(result, d); // 14 + 6 = 20
        counter.Increment();

        var decrypted = _bfvEngine.Decrypt(result);
        decrypted.Should().Be(20, "3+4=7, 7*2=14, 14+6=20");

        _output.WriteLine($"Mixed BFV ops: {counter.Summary}, result={decrypted}");
    }

    public void Dispose()
    {
        _bfvKeyManager.Dispose();
        _ckksKeyManager.Dispose();
        GC.SuppressFinalize(this);
    }
}
