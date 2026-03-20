using System.Diagnostics;
using CyTypes.Core.Policy;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class PerformanceOverhead
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 10: Performance Overhead - CyTypes vs Native C#");

        ConsoleHelpers.PrintNote("CyTypes encrypt every value in memory with AES-256-GCM.");
        ConsoleHelpers.PrintNote("This demo measures the cost of that protection vs raw .NET primitives.");
        ConsoleHelpers.PrintNote("Using SecurityPolicy.Performance to avoid decryption limits.");
        Console.WriteLine();

        // ── CyInt vs int ──
        ConsoleHelpers.PrintSubHeader("CyInt vs int (10,000 iterations)");

        var (intCreate, cyIntCreate) = MeasureOverhead(
            "Creation", 10_000,
            () => { int x = 42; _ = x; },
            () => { using var cx = new CyInt(42, SecurityPolicy.Performance); });
        PrintRow("Creation", intCreate, cyIntCreate);

        var (intAdd, cyIntAdd) = MeasureOverhead(
            "Addition", 10_000,
            () => { int a = 42, b = 58; _ = a + b; },
            () =>
            {
                using var a = new CyInt(42, SecurityPolicy.Performance);
                using var b = new CyInt(58, SecurityPolicy.Performance);
                using var r = a + b;
            });
        PrintRow("Addition", intAdd, cyIntAdd);

        var (intMul, cyIntMul) = MeasureOverhead(
            "Multiplication", 10_000,
            () => { int a = 42, b = 7; _ = a * b; },
            () =>
            {
                using var a = new CyInt(42, SecurityPolicy.Performance);
                using var b = new CyInt(7, SecurityPolicy.Performance);
                using var r = a * b;
            });
        PrintRow("Multiplication", intMul, cyIntMul);

        var (intDiv, cyIntDiv) = MeasureOverhead(
            "Division", 10_000,
            () => { int a = 100, b = 7; _ = a / b; },
            () =>
            {
                using var a = new CyInt(100, SecurityPolicy.Performance);
                using var b = new CyInt(7, SecurityPolicy.Performance);
                using var r = a / b;
            });
        PrintRow("Division", intDiv, cyIntDiv);
        Console.WriteLine();

        // ── CyDouble vs double ──
        ConsoleHelpers.PrintSubHeader("CyDouble vs double (10,000 iterations)");

        var (dblCreate, cyDblCreate) = MeasureOverhead(
            "Creation", 10_000,
            () => { double x = 3.14; _ = x; },
            () => { using var cx = new CyDouble(3.14, SecurityPolicy.Performance); });
        PrintRow("Creation", dblCreate, cyDblCreate);

        var (dblAdd, cyDblAdd) = MeasureOverhead(
            "Addition", 10_000,
            () => { double a = 3.14, b = 2.71; _ = a + b; },
            () =>
            {
                using var a = new CyDouble(3.14, SecurityPolicy.Performance);
                using var b = new CyDouble(2.71, SecurityPolicy.Performance);
                using var r = a + b;
            });
        PrintRow("Addition", dblAdd, cyDblAdd);

        var (dblMul, cyDblMul) = MeasureOverhead(
            "Multiplication", 10_000,
            () => { double a = 3.14, b = 2.71; _ = a * b; },
            () =>
            {
                using var a = new CyDouble(3.14, SecurityPolicy.Performance);
                using var b = new CyDouble(2.71, SecurityPolicy.Performance);
                using var r = a * b;
            });
        PrintRow("Multiplication", dblMul, cyDblMul);
        Console.WriteLine();

        // ── CyDecimal vs decimal ──
        ConsoleHelpers.PrintSubHeader("CyDecimal vs decimal (10,000 iterations)");

        var (decCreate, cyDecCreate) = MeasureOverhead(
            "Creation", 10_000,
            () => { decimal x = 19.99m; _ = x; },
            () => { using var cx = new CyDecimal(19.99m, SecurityPolicy.Performance); });
        PrintRow("Creation", decCreate, cyDecCreate);

        var (decAdd, cyDecAdd) = MeasureOverhead(
            "Addition", 10_000,
            () => { decimal a = 19.99m, b = 5.01m; _ = a + b; },
            () =>
            {
                using var a = new CyDecimal(19.99m, SecurityPolicy.Performance);
                using var b = new CyDecimal(5.01m, SecurityPolicy.Performance);
                using var r = a + b;
            });
        PrintRow("Addition", decAdd, cyDecAdd);

        var (decMul, cyDecMul) = MeasureOverhead(
            "Multiplication", 10_000,
            () => { decimal a = 19.99m, b = 3m; _ = a * b; },
            () =>
            {
                using var a = new CyDecimal(19.99m, SecurityPolicy.Performance);
                using var b = new CyDecimal(3m, SecurityPolicy.Performance);
                using var r = a * b;
            });
        PrintRow("Multiplication", decMul, cyDecMul);
        Console.WriteLine();

        // ── CyString vs string ──
        ConsoleHelpers.PrintSubHeader("CyString vs string (5,000 iterations)");

        var (strCreate, cyStrCreate) = MeasureOverhead(
            "Creation", 5_000,
            () => { string s = "Hello, World!"; _ = s; },
            () => { using var cs = new CyString("Hello, World!", SecurityPolicy.Performance); });
        PrintRow("Creation", strCreate, cyStrCreate);

        var (strConcat, cyStrConcat) = MeasureOverhead(
            "Concatenation", 5_000,
            () => { string a = "Hello"; string b = " World"; _ = a + b; },
            () =>
            {
                using var a = new CyString("Hello", SecurityPolicy.Performance);
                using var b = new CyString(" World", SecurityPolicy.Performance);
                using var r = a + b;
            });
        PrintRow("Concatenation", strConcat, cyStrConcat);

        var (strCmp, cyStrCmp) = MeasureOverhead(
            "Comparison", 5_000,
            () => { string a = "Hello"; string b = "Hello"; _ = a == b; },
            () =>
            {
                using var a = new CyString("Hello", SecurityPolicy.Performance);
                using var b = new CyString("Hello", SecurityPolicy.Performance);
                _ = a == b;
            });
        PrintRow("Comparison", strCmp, cyStrCmp);
        Console.WriteLine();

        // ── Summary Table ──
        ConsoleHelpers.PrintSubHeader("Summary: Overhead Factors");
        ConsoleHelpers.PrintNote("Overhead = CyType time / Native time. Higher = more overhead.");
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  {"Operation",-30} {"Native (ticks)",-18} {"CyType (ticks)",-18} {"Overhead",10}");
        Console.WriteLine($"  {new string('-', 76)}");
        Console.ResetColor();

        PrintSummaryRow("CyInt Creation", intCreate, cyIntCreate);
        PrintSummaryRow("CyInt Addition", intAdd, cyIntAdd);
        PrintSummaryRow("CyInt Multiplication", intMul, cyIntMul);
        PrintSummaryRow("CyInt Division", intDiv, cyIntDiv);
        PrintSummaryRow("CyDouble Creation", dblCreate, cyDblCreate);
        PrintSummaryRow("CyDouble Addition", dblAdd, cyDblAdd);
        PrintSummaryRow("CyDouble Multiplication", dblMul, cyDblMul);
        PrintSummaryRow("CyDecimal Creation", decCreate, cyDecCreate);
        PrintSummaryRow("CyDecimal Addition", decAdd, cyDecAdd);
        PrintSummaryRow("CyDecimal Multiplication", decMul, cyDecMul);
        PrintSummaryRow("CyString Creation", strCreate, cyStrCreate);
        PrintSummaryRow("CyString Concatenation", strConcat, cyStrConcat);
        PrintSummaryRow("CyString Comparison", strCmp, cyStrCmp);

        Console.WriteLine();
        ConsoleHelpers.PrintNote("Overhead is expected — every CyType operation involves AES-256-GCM encrypt/decrypt,");
        ConsoleHelpers.PrintNote("pinned memory allocation, and secure key management. This is the cost of protection.");
    }

    private static (long nativeTicks, long cyTicks) MeasureOverhead(
        string label, int iterations, Action nativeAction, Action cyAction)
    {
        // Warmup
        for (int i = 0; i < 100; i++)
        {
            nativeAction();
            cyAction();
        }

        var sw = new Stopwatch();

        // Measure native
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            nativeAction();
        sw.Stop();
        long nativeTicks = sw.ElapsedTicks;

        // Measure CyType
        sw.Restart();
        for (int i = 0; i < iterations; i++)
            cyAction();
        sw.Stop();
        long cyTicks = sw.ElapsedTicks;

        return (nativeTicks, cyTicks);
    }

    private static void PrintRow(string operation, long nativeTicks, long cyTicks)
    {
        double factor = nativeTicks > 0 ? (double)cyTicks / nativeTicks : cyTicks;
        ConsoleHelpers.PrintInfo($"{operation,-20} Native: {nativeTicks,10} ticks | CyType: {cyTicks,10} ticks | Overhead: {factor:F0}x");
    }

    private static void PrintSummaryRow(string operation, long nativeTicks, long cyTicks)
    {
        double factor = nativeTicks > 0 ? (double)cyTicks / nativeTicks : cyTicks;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"  {operation,-30}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($" {nativeTicks,14}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($" {cyTicks,17}");
        Console.ForegroundColor = factor > 100 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.WriteLine($" {factor,10:F0}x");
        Console.ResetColor();
    }
}
