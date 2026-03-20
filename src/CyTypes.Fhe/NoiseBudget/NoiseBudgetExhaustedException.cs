namespace CyTypes.Fhe.NoiseBudget;

/// <summary>
/// Thrown when the noise budget of an FHE ciphertext is exhausted, making further
/// homomorphic operations impossible without decryption corruption.
/// </summary>
public sealed class NoiseBudgetExhaustedException : InvalidOperationException
{
    /// <summary>Gets the remaining noise budget in bits.</summary>
    public int RemainingBits { get; }

    /// <summary>Gets the minimum required noise budget in bits.</summary>
    public int MinimumRequired { get; }

    /// <summary>Initializes a new instance with remaining and minimum budget information.</summary>
    public NoiseBudgetExhaustedException(int remainingBits, int minimumRequired)
        : base($"Noise budget exhausted: {remainingBits} bits remaining, {minimumRequired} required. " +
               "Consider using larger SEAL parameters or reducing the computation depth.")
    {
        RemainingBits = remainingBits;
        MinimumRequired = minimumRequired;
    }
}
