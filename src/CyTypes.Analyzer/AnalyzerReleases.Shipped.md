; Shipped analyzer releases
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

## Release 1.0.0

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|-------
CY0001 | Security | Warning | CyTypesAnalyzer - ToInsecureValue() called outside [InsecureAccess] context
CY0002 | Security | Warning | CyTypesAnalyzer - CyType used in string interpolation
CY0003 | Security | Error | CyTypesAnalyzer - Explicit cast from CyType discards security tracking
CY0004 | Security | Warning | CyTypesAnalyzer - CyType not disposed
