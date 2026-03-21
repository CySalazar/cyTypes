using BenchmarkDotNet.Running;
using CyTypes.Benchmarks.Application.Soak;

namespace CyTypes.Benchmarks.Application;

public class Program
{
    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("soak", StringComparison.OrdinalIgnoreCase))
        {
            var minutes = args.Length > 1 ? int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 30;
            return SoakTestRunner.Run(minutes);
        }

        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
        return 0;
    }
}
