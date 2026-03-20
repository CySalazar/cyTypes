using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using Xunit;

namespace CyTypes.Analyzer.Tests;

using AnalyzerTest = CSharpAnalyzerTest<CyTypesAnalyzer, DefaultVerifier>;

public sealed class CyTypesAnalyzerTests
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
            }
        }
        namespace CyTypes.Primitives
        {
            public sealed class CyInt : CyTypes.Primitives.Shared.CyTypeBase<CyInt, int>
            {
                public int ToInsecureInt() => ToInsecureValue();
            }
        }
        [System.AttributeUsage(System.AttributeTargets.Method)]
        public sealed class InsecureAccessAttribute : System.Attribute { }
        """;

    [Fact]
    public async Task CY0001_ToInsecureValue_outside_InsecureAccess_warns()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using var x = new CyTypes.Primitives.CyInt();
                        var v = {|#0:x.ToInsecureInt()|};
                    }
                }
                """,
            ExpectedDiagnostics =
            {
                new DiagnosticResult(CyTypesAnalyzer.DiagnosticIdInsecureAccess, DiagnosticSeverity.Warning)
                    .WithLocation(0)
                    .WithArguments("ToInsecureInt"),
            },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0001_ToInsecureValue_inside_InsecureAccess_no_warning()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    [InsecureAccess]
                    void Run()
                    {
                        using var x = new CyTypes.Primitives.CyInt();
                        var v = x.ToInsecureInt();
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0002_string_interpolation_warns()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using var x = new CyTypes.Primitives.CyInt();
                        var s = $"value = {|#0:{x}|}";
                    }
                }
                """,
            ExpectedDiagnostics =
            {
                new DiagnosticResult(CyTypesAnalyzer.DiagnosticIdStringInterpolation, DiagnosticSeverity.Warning)
                    .WithLocation(0)
                    .WithArguments("CyInt"),
            },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0004_missing_dispose_warns()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        var {|#0:x|} = new CyTypes.Primitives.CyInt();
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

    [Fact]
    public async Task CY0004_using_declaration_no_warning()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        using var x = new CyTypes.Primitives.CyInt();
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task CY0004_explicit_dispose_call_no_warning()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    void Run()
                    {
                        var x = new CyTypes.Primitives.CyInt();
                        x.Dispose();
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }

    [Fact]
    public async Task No_diagnostics_on_clean_code()
    {
        var test = new AnalyzerTest
        {
            TestCode = CyTypeStubs + """

                class Test
                {
                    [InsecureAccess]
                    void Run()
                    {
                        using var x = new CyTypes.Primitives.CyInt();
                        var v = x.ToInsecureInt();
                    }
                }
                """,
            ExpectedDiagnostics = { },
        };

        test.TestBehaviors = TestBehaviors.SkipGeneratedCodeCheck;
        await test.RunAsync();
    }
}
