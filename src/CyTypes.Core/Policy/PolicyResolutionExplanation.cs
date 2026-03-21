namespace CyTypes.Core.Policy;

/// <summary>
/// Explains how a resolved policy was computed from two input policies,
/// showing per-component resolution details.
/// </summary>
/// <param name="ResolvedName">The name of the resolved policy.</param>
/// <param name="Components">Per-component resolution details.</param>
public sealed record PolicyResolutionExplanation(
    string ResolvedName,
    IReadOnlyList<ComponentResolution> Components);

/// <summary>
/// Describes how a single policy component was resolved.
/// </summary>
/// <param name="ComponentName">The name of the policy component (e.g., "Arithmetic", "Taint").</param>
/// <param name="LeftValue">The value from the left policy.</param>
/// <param name="RightValue">The value from the right policy.</param>
/// <param name="ResolvedValue">The resolved (winning) value.</param>
/// <param name="Rule">A short description of the resolution rule applied.</param>
public sealed record ComponentResolution(
    string ComponentName,
    string LeftValue,
    string RightValue,
    string ResolvedValue,
    string Rule);
