using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Fhe.NoiseBudget;

/// <summary>
/// Tracks noise budget for FHE ciphertexts and raises warnings or exceptions
/// when the budget is low or exhausted.
/// </summary>
public sealed class NoiseBudgetTracker
{
    private readonly IFheEngine _engine;
    private readonly int _minimumBudget;
    private int _initialBudget;

    private readonly double _warningThreshold;

    /// <summary>Raised when the noise budget drops below the warning threshold of the initial budget.</summary>
    public event Action<int, int>? BudgetLow;

    /// <summary>
    /// Initializes a new tracker with the specified engine and minimum budget threshold.
    /// </summary>
    /// <param name="engine">The FHE engine to query noise budget from.</param>
    /// <param name="minimumBudget">The minimum acceptable noise budget in bits (default: 1).</param>
    /// <param name="warningThreshold">The fraction of initial budget below which a warning is raised (default: 0.2 = 20%).</param>
    public NoiseBudgetTracker(IFheEngine engine, int minimumBudget = 1, double warningThreshold = 0.2)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _minimumBudget = minimumBudget;
        if (warningThreshold is <= 0.0 or >= 1.0)
            throw new ArgumentOutOfRangeException(nameof(warningThreshold), "Must be between 0 and 1 exclusive.");
        _warningThreshold = warningThreshold;
    }

    /// <summary>
    /// Records the initial noise budget from a freshly encrypted ciphertext.
    /// </summary>
    public void RecordInitialBudget(byte[] ciphertext)
    {
        _initialBudget = _engine.GetNoiseBudget(ciphertext);
    }

    /// <summary>
    /// Checks the noise budget of a ciphertext after an operation.
    /// Raises <see cref="BudgetLow"/> if below 20% of initial, and throws
    /// <see cref="NoiseBudgetExhaustedException"/> if at or below the minimum.
    /// </summary>
    /// <returns>The current noise budget in bits.</returns>
    public int CheckBudget(byte[] ciphertext)
    {
        var budget = _engine.GetNoiseBudget(ciphertext);

        if (budget <= _minimumBudget)
            throw new NoiseBudgetExhaustedException(budget, _minimumBudget);

        if (_initialBudget > 0 && budget < _initialBudget * _warningThreshold)
            BudgetLow?.Invoke(budget, _initialBudget);

        return budget;
    }
}
