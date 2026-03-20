using System.Numerics;

namespace CyTypes.Primitives.Shared;

/// <summary>Interface for encrypted numeric CyType instances.</summary>
public interface ICyNumeric<TSelf> : ICyType
    where TSelf : ICyNumeric<TSelf>
{
    /// <summary>Indicates whether fully homomorphic encryption is supported for this type under the current policy.</summary>
    bool SupportsFhe { get; }
}
