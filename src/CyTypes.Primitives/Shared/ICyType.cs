using CyTypes.Core.Policy;

namespace CyTypes.Primitives.Shared;

/// <summary>Base interface for all encrypted CyType instances.</summary>
public interface ICyType : IDisposable, IAsyncDisposable
{
    /// <summary>Gets the security policy governing this instance.</summary>
    SecurityPolicy Policy { get; }
    /// <summary>Gets the unique identifier for this instance.</summary>
    Guid InstanceId { get; }
    /// <summary>Gets a value indicating whether this instance has been compromised.</summary>
    bool IsCompromised { get; }
    /// <summary>Gets a value indicating whether this instance has been tainted.</summary>
    bool IsTainted { get; }
    /// <summary>Gets a value indicating whether this instance has been disposed.</summary>
    bool IsDisposed { get; }
}
