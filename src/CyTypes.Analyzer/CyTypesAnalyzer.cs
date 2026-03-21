using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace CyTypes.Analyzer;

/// <summary>Roslyn analyzer that detects insecure usage patterns of CyType instances.</summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CyTypesAnalyzer : DiagnosticAnalyzer
{
    /// <summary>Diagnostic ID for insecure access outside an [InsecureAccess] context.</summary>
    public const string DiagnosticIdInsecureAccess = "CY0001";
    /// <summary>Diagnostic ID for CyType usage in string interpolation.</summary>
    public const string DiagnosticIdStringInterpolation = "CY0002";
    /// <summary>Diagnostic ID for explicit casts that discard security tracking.</summary>
    public const string DiagnosticIdFireAndForgetCast = "CY0003";
    /// <summary>Diagnostic ID for CyType variables that are not disposed.</summary>
    public const string DiagnosticIdMissingDispose = "CY0004";
    /// <summary>Diagnostic ID for CyType used as dictionary key or hash set element.</summary>
    public const string DiagnosticIdIdentityHashCode = "CY0005";

    private const string Category = "Security";
    private const string CyTypeBaseTypeName = "CyTypeBase";
    private const string ICyTypeName = "ICyType";

    private static readonly DiagnosticDescriptor RuleInsecureAccess = new(
        DiagnosticIdInsecureAccess,
        "ToInsecureValue() called outside [InsecureAccess] context",
        "Call to '{0}' exposes encrypted data. Consider wrapping in an [InsecureAccess] attributed method.",
        Category,
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor RuleStringInterpolation = new(
        DiagnosticIdStringInterpolation,
        "CyType used in string interpolation",
        "CyType '{0}' used in string interpolation may leak security metadata. Use explicit formatting.",
        Category,
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor RuleFireAndForgetCast = new(
        DiagnosticIdFireAndForgetCast,
        "Explicit cast from CyType discards security tracking",
        "Explicit cast from '{0}' to native type discards security tracking. Value is compromised after cast.",
        Category,
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor RuleMissingDispose = new(
        DiagnosticIdMissingDispose,
        "CyType not disposed",
        "CyType '{0}' should be disposed via 'using' statement or explicit Dispose() call to zero sensitive memory",
        Category,
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor RuleIdentityHashCode = new(
        DiagnosticIdIdentityHashCode,
        "CyType used as dictionary key or HashSet element",
        "CyType '{0}' uses identity-based GetHashCode(). Two instances with the same encrypted value will have different hash codes.",
        Category,
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    /// <summary>Gets the set of diagnostic descriptors this analyzer can produce.</summary>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(RuleInsecureAccess, RuleStringInterpolation, RuleFireAndForgetCast, RuleMissingDispose, RuleIdentityHashCode);

    /// <summary>Registers syntax node actions for detecting insecure CyType usage patterns.</summary>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeInterpolation, SyntaxKind.Interpolation);
        context.RegisterSyntaxNodeAction(AnalyzeCastExpression, SyntaxKind.CastExpression);
        context.RegisterSyntaxNodeAction(AnalyzeLocalDeclaration, SyntaxKind.LocalDeclarationStatement);
        context.RegisterSyntaxNodeAction(AnalyzeGenericName, SyntaxKind.GenericName);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return;

        var methodName = memberAccess.Name.Identifier.Text;
        if (!methodName.StartsWith("ToInsecure", System.StringComparison.Ordinal))
            return;

        // Check if the containing method has [InsecureAccess] attribute
        var containingMethod = invocation.FirstAncestorOrSelf<MethodDeclarationSyntax>();
        if (containingMethod != null && HasInsecureAccessAttribute(containingMethod))
            return;

        var symbolInfo = context.SemanticModel.GetSymbolInfo(memberAccess.Expression);
        if (symbolInfo.Symbol is not ILocalSymbol and not IParameterSymbol and not IFieldSymbol and not IPropertySymbol)
            return;

        var type = GetTypeSymbol(symbolInfo.Symbol);
        if (type != null && IsCyType(type))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                RuleInsecureAccess, invocation.GetLocation(), methodName));
        }
    }

    private static void AnalyzeInterpolation(SyntaxNodeAnalysisContext context)
    {
        var interpolation = (InterpolationSyntax)context.Node;
        var typeInfo = context.SemanticModel.GetTypeInfo(interpolation.Expression);

        if (typeInfo.Type != null && IsCyType(typeInfo.Type))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                RuleStringInterpolation, interpolation.GetLocation(), typeInfo.Type.Name));
        }
    }

    private static void AnalyzeCastExpression(SyntaxNodeAnalysisContext context)
    {
        var castExpression = (CastExpressionSyntax)context.Node;
        var typeInfo = context.SemanticModel.GetTypeInfo(castExpression.Expression);

        if (typeInfo.Type != null && IsCyType(typeInfo.Type))
        {
            // Check if the result is being used (not just a standalone expression statement)
            if (castExpression.Parent is ExpressionStatementSyntax)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    RuleFireAndForgetCast, castExpression.GetLocation(), typeInfo.Type.Name));
            }
        }
    }

    private static void AnalyzeLocalDeclaration(SyntaxNodeAnalysisContext context)
    {
        var localDeclaration = (LocalDeclarationStatementSyntax)context.Node;

        // Skip 'using' declarations
        if (localDeclaration.UsingKeyword != default)
            return;

        foreach (var variable in localDeclaration.Declaration.Variables)
        {
            var symbolInfo = context.SemanticModel.GetDeclaredSymbol(variable);
            if (symbolInfo is not ILocalSymbol local)
                continue;

            if (!IsCyType(local.Type))
                continue;

            // Check if the variable is disposed in the enclosing block
            var block = localDeclaration.FirstAncestorOrSelf<BlockSyntax>();
            if (block == null)
                continue;

            var variableName = variable.Identifier.Text;
            var hasDispose = false;

            foreach (var statement in block.Statements)
            {
                if (statement is ExpressionStatementSyntax exprStmt &&
                    exprStmt.Expression is InvocationExpressionSyntax inv &&
                    inv.Expression is MemberAccessExpressionSyntax ma &&
                    ma.Name.Identifier.Text == "Dispose" &&
                    ma.Expression is IdentifierNameSyntax id &&
                    id.Identifier.Text == variableName)
                {
                    hasDispose = true;
                    break;
                }
            }

            if (!hasDispose)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    RuleMissingDispose, variable.Identifier.GetLocation(), local.Type.Name));
            }
        }
    }

    private static void AnalyzeGenericName(SyntaxNodeAnalysisContext context)
    {
        var genericName = (GenericNameSyntax)context.Node;
        var name = genericName.Identifier.Text;

        // Check for Dictionary<CyType, ...> or HashSet<CyType>
        if (name is not ("Dictionary" or "HashSet" or "ConcurrentDictionary"))
            return;

        var typeArgs = genericName.TypeArgumentList.Arguments;
        if (typeArgs.Count == 0) return;

        // For Dictionary/ConcurrentDictionary, check the first type argument (the key)
        // For HashSet, check the first (only) type argument
        var targetArg = typeArgs[0];
        var typeInfo = context.SemanticModel.GetTypeInfo(targetArg);

        if (typeInfo.Type != null && IsCyType(typeInfo.Type))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                RuleIdentityHashCode, targetArg.GetLocation(), typeInfo.Type.Name));
        }
    }

    private static bool IsCyType(ITypeSymbol type)
    {
        // Check if the type implements ICyType or inherits from CyTypeBase
        if (type.Name == ICyTypeName)
            return true;

        foreach (var iface in type.AllInterfaces)
        {
            if (iface.Name == ICyTypeName)
                return true;
        }

        var current = type.BaseType;
        while (current != null)
        {
            if (current.Name == CyTypeBaseTypeName)
                return true;
            current = current.BaseType;
        }

        return false;
    }

    private static bool HasInsecureAccessAttribute(MethodDeclarationSyntax method)
    {
        foreach (var attrList in method.AttributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();
                if (name is "InsecureAccess" or "InsecureAccessAttribute")
                    return true;
            }
        }
        return false;
    }

    private static ITypeSymbol? GetTypeSymbol(ISymbol? symbol) => symbol switch
    {
        ILocalSymbol local => local.Type,
        IParameterSymbol param => param.Type,
        IFieldSymbol field => field.Type,
        IPropertySymbol prop => prop.Type,
        _ => null
    };
}
