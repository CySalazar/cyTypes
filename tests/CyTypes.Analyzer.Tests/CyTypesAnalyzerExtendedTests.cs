using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using Xunit;

namespace CyTypes.Analyzer.Tests;

using AnalyzerTest = CSharpAnalyzerTest<CyTypesAnalyzer, DefaultVerifier>;

public sealed class CyTypesAnalyzerExtendedTests
{
    private const string CyTypeStubs = """
        namespace CyTypes.Primitives.Shared
        {
            public interface ICyType : System.IDisposable, System.IAsyncDisposable { }
            public abstract class CyTypeBase<TSelf, TNative> : ICyType
                where TSelf : CyTypeBase<TSelf, TNative>
            {
                public TNative ToInsecureValue() => default!;
                public void Dispose() { }
                public System.Threading.Tasks.ValueTask DisposeAsync() => default;
                public static explicit operator TNative(CyTypeBase<TSelf, TNative> v) => default!;
            }
        }
        namespace CyTypes.Primitives
        {
            public sealed class CyInt : CyTypes.Primitives.Shared.CyTypeBase<CyInt, int>
            {
                public int ToInsecureInt() => ToInsecureValue();
            }
            public sealed class CyString : CyTypes.Primitives.Shared.CyTypeBase<CyString, string>
            {
                public string ToInsecureString() => ToInsecureValue();
            }
        }
        [System.AttributeUsage(System.AttributeTargets.Method)]
        public sealed class InsecureAccessAttribute : System.Attribute { }
        """;

    // === CY0003 — Explicit cast tests ===

    [Fact]
    public async Task CY0003_ToString_no_warning()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using var x = new CyTypes.Primitives.CyInt();
                        // No explicit cast — should not trigger CY0003
                        var s = x.ToString();
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    // === CY0001 — Extended edge cases ===

    [Fact]
    public async Task CY0001_ToInsecureString_outside_context_warns()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using var s = new CyTypes.Primitives.CyString();
                        var v = {|#0:s.ToInsecureString()|};
                    }
                }
                """,
            ExpectedDiagnostics =
            {
                new DiagnosticResult(CyTypesAnalyzer.DiagnosticIdInsecureAccess, DiagnosticSeverity.Warning)
                    .WithLocation(0)
                    .WithArguments("ToInsecureString"),
            },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0001_ToInsecureValue_outside_context_warns()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using var x = new CyTypes.Primitives.CyInt();
                        var v = {|#0:x.ToInsecureValue()|};
                    }
                }
                """,
            ExpectedDiagnostics =
            {
                new DiagnosticResult(CyTypesAnalyzer.DiagnosticIdInsecureAccess, DiagnosticSeverity.Warning)
                    .WithLocation(0)
                    .WithArguments("ToInsecureValue"),
            },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    // === CY0002 — Extended interpolation cases ===

    [Fact]
    public async Task CY0002_multiple_CyTypes_in_interpolation_warns_for_each()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using var a = new CyTypes.Primitives.CyInt();
                        using var b = new CyTypes.Primitives.CyInt();
                        var s = $"{|#0:{a}|} and {|#1:{b}|}";
                    }
                }
                """,
            ExpectedDiagnostics =
            {
                new DiagnosticResult(CyTypesAnalyzer.DiagnosticIdStringInterpolation, DiagnosticSeverity.Warning)
                    .WithLocation(0)
                    .WithArguments("CyInt"),
                new DiagnosticResult(CyTypesAnalyzer.DiagnosticIdStringInterpolation, DiagnosticSeverity.Warning)
                    .WithLocation(1)
                    .WithArguments("CyInt"),
            },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0002_non_CyType_in_interpolation_no_warning()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        int x = 42;
                        var s = $"value = {x}";
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    // === CY0004 — Extended dispose cases ===

    [Fact]
    public async Task CY0004_using_statement_block_no_warning()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using (var x = new CyTypes.Primitives.CyInt())
                        {
                        }
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0004_returned_value_still_warns()
    {
        // The analyzer does not track data flow for returned values,
        // so it still warns about missing dispose even if the value is returned.
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    CyTypes.Primitives.CyInt Create()
                    {
                        var {|#0:x|} = new CyTypes.Primitives.CyInt();
                        return x;
                    }
                }
                """,
            ExpectedDiagnostics =
            {
                new DiagnosticResult(CyTypesAnalyzer.DiagnosticIdMissingDispose, DiagnosticSeverity.Warning)
                    .WithLocation(0)
                    .WithArguments("CyInt"),
            },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    // === CY0005 — Extended identity hash code cases ===

    [Fact]
    public async Task CY0005_SortedSet_with_CyType_no_warning()
    {
        // SortedSet is not checked by the analyzer (only Dictionary and HashSet)
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        var s = new System.Collections.Generic.SortedSet<CyTypes.Primitives.CyInt>();
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0005_List_with_CyType_no_warning()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        var l = new System.Collections.Generic.List<CyTypes.Primitives.CyInt>();
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }
}
