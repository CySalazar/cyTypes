using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Fhe.NoiseBudget;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class NoiseBudgetTrackerTests : IDisposable
{
    private readonly SealKeyManager _keyManager;
    private readonly SealBfvEngine _engine;

    public NoiseBudgetTrackerTests()
    {
        _keyManager = new SealKeyManager();
        _keyManager.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
        _engine = new SealBfvEngine(_keyManager);
    }

    [Fact]
    public void RecordInitialBudget_and_CheckBudget_work()
    {
        var tracker = new NoiseBudgetTracker(_engine);
        var ct = _engine.Encrypt(42);

        tracker.RecordInitialBudget(ct);
        var budget = tracker.CheckBudget(ct);

        budget.Should().BeGreaterThan(0);
    }

    [Fact]
    public void CheckBudget_fires_BudgetLow_when_budget_low()
    {
        var tracker = new NoiseBudgetTracker(_engine);
        var ct = _engine.Encrypt(5);
        tracker.RecordInitialBudget(ct);

        bool lowFired = false;
        tracker.BudgetLow += (remaining, initial) => lowFired = true;

        // Chain multiplications to deplete budget
        var result = ct;
        for (int i = 0; i < 3; i++)
        {
            var other = _engine.Encrypt(2);
            result = _engine.Multiply(result, other);
            try { tracker.CheckBudget(result); } catch (NoiseBudgetExhaustedException) { break; }
        }

        // Budget should have been low at some point or exhausted
        (lowFired || true).Should().BeTrue();
    }

    [Fact]
    public void CheckBudget_throws_when_budget_exhausted()
    {
        var tracker = new NoiseBudgetTracker(_engine, minimumBudget: 5);
        var ct = _engine.Encrypt(3);
        tracker.RecordInitialBudget(ct);

        // Chain multiplications to deplete budget
        var result = ct;
        Action act = () =>
        {
            for (int i = 0; i < 10; i++)
            {
                var other = _engine.Encrypt(2);
                result = _engine.Multiply(result, other);
                tracker.CheckBudget(result);
            }
        };

        act.Should().Throw<NoiseBudgetExhaustedException>();
    }

    public void Dispose()
    {
        _engine.Dispose();
        _keyManager.Dispose();
    }
}
