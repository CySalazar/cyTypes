namespace CyTypes.Core.Policy.Components;

/// <summary>
/// Specifies the FHE scheme used for homomorphic encryption.
/// </summary>
public enum FheScheme
{
    /// <summary>Brakerski/Fan-Vercauteren scheme for exact integer arithmetic.</summary>
    BFV = 0,

    /// <summary>Cheon-Kim-Kim-Song scheme for approximate real-number arithmetic.</summary>
    CKKS = 1
}
