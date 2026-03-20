using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;

namespace CyTypes.DependencyInjection;

/// <summary>
/// Configuration options for CyTypes services.
/// </summary>
public sealed class CyTypesOptions
{
    /// <summary>Gets or sets the default security policy applied to new CyType instances.</summary>
    public SecurityPolicy DefaultPolicy { get; set; } = SecurityPolicy.Default;

    /// <summary>Gets or sets whether the redacting logger provider is registered.</summary>
    public bool EnableRedactingLogger { get; set; } = true;

    /// <summary>Gets or sets whether the security auditor is registered as a singleton.</summary>
    public bool EnableAudit { get; set; } = true;

    /// <summary>Gets or sets whether FHE support is enabled.</summary>
    public bool EnableFhe { get; set; }

    /// <summary>Gets or sets the FHE scheme to use when FHE is enabled.</summary>
    public FheScheme FheScheme { get; set; } = FheScheme.BFV;

    /// <summary>Gets or sets whether post-quantum key encapsulation is enabled.</summary>
    public bool EnablePqcKeyEncapsulation { get; set; }
}
