using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.Security.Tests.Timing;

/// <summary>
/// Timing leak detection tests using the dudect methodology.
/// Reference: Reparaz, Balasch, Verbauwhede — "dude, is my code constant time?" (2017).
/// Uses Welch's t-test to detect statistically significant timing differences
/// between correct and incorrect MAC comparisons.
/// Pass criterion: |t| &lt; 4.5 (p &lt; 0.00001 two-tailed).
/// </summary>
public class TimingLeakTests
{
    private readonly ITestOutputHelper _output;
    private const int SampleCount = 10_000;
    private const double TStatisticThreshold = 4.5;

    public TimingLeakTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void HmacVerify_ConstantTime_FirstByteDifference()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var data = new byte[64];
        RandomNumberGenerator.Fill(data);
        var correctMac = HmacComparer.Compute(key, data);

        // MAC with first byte different
        var wrongMac = (byte[])correctMac.Clone();
        wrongMac[0] ^= 0xFF;

        var tStatistic = MeasureTimingDifference(key, data, correctMac, wrongMac);

        _output.WriteLine($"[dudect] First-byte difference: t-statistic = {tStatistic:F4} (threshold: {TStatisticThreshold})");

        Math.Abs(tStatistic).Should().BeLessThan(TStatisticThreshold,
            because: "HmacComparer.Verify must be constant-time (dudect methodology, first-byte difference)");
    }

    [Fact]
    public void HmacVerify_ConstantTime_LastByteDifference()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var data = new byte[64];
        RandomNumberGenerator.Fill(data);
        var correctMac = HmacComparer.Compute(key, data);

        // MAC with last byte different
        var wrongMac = (byte[])correctMac.Clone();
        wrongMac[^1] ^= 0xFF;

        var tStatistic = MeasureTimingDifference(key, data, correctMac, wrongMac);

        _output.WriteLine($"[dudect] Last-byte difference: t-statistic = {tStatistic:F4} (threshold: {TStatisticThreshold})");

        Math.Abs(tStatistic).Should().BeLessThan(TStatisticThreshold,
            because: "HmacComparer.Verify must be constant-time (dudect methodology, last-byte difference)");
    }

    [Fact]
    public void HmacVerify_ConstantTime_AllBytesDifferent()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var data = new byte[64];
        RandomNumberGenerator.Fill(data);
        var correctMac = HmacComparer.Compute(key, data);

        // Completely different MAC
        var wrongMac = new byte[correctMac.Length];
        RandomNumberGenerator.Fill(wrongMac);

        var tStatistic = MeasureTimingDifference(key, data, correctMac, wrongMac);

        _output.WriteLine($"[dudect] All-bytes difference: t-statistic = {tStatistic:F4} (threshold: {TStatisticThreshold})");

        Math.Abs(tStatistic).Should().BeLessThan(TStatisticThreshold,
            because: "HmacComparer.Verify must be constant-time (dudect methodology, all bytes different)");
    }

    /// <summary>
    /// Measures timing difference between verifying two different MACs using Welch's t-test.
    /// Interleaves measurements to minimize systematic bias.
    /// </summary>
    private static double MeasureTimingDifference(byte[] key, byte[] data, byte[] macA, byte[] macB)
    {
        var timingsA = new double[SampleCount];
        var timingsB = new double[SampleCount];

        // Warmup: JIT compilation and CPU cache warming
        for (int i = 0; i < 1000; i++)
        {
            HmacComparer.Verify(key, data, macA);
            HmacComparer.Verify(key, data, macB);
        }

        // Interleaved measurement to minimize systematic bias
        for (int i = 0; i < SampleCount; i++)
        {
            // Alternate order to reduce ordering bias
            if (i % 2 == 0)
            {
                timingsA[i] = MeasureSingle(key, data, macA);
                timingsB[i] = MeasureSingle(key, data, macB);
            }
            else
            {
                timingsB[i] = MeasureSingle(key, data, macB);
                timingsA[i] = MeasureSingle(key, data, macA);
            }
        }

        return WelchTTest(timingsA, timingsB);
    }

    private static double MeasureSingle(byte[] key, byte[] data, byte[] mac)
    {
        var start = Stopwatch.GetTimestamp();
        HmacComparer.Verify(key, data, mac);
        var end = Stopwatch.GetTimestamp();
        return end - start;
    }

    /// <summary>
    /// Computes Welch's t-statistic for two independent samples.
    /// </summary>
    private static double WelchTTest(double[] a, double[] b)
    {
        var meanA = Mean(a);
        var meanB = Mean(b);
        var varA = Variance(a, meanA);
        var varB = Variance(b, meanB);

        var denominator = Math.Sqrt(varA / a.Length + varB / b.Length);
        if (denominator < 1e-15) return 0.0;

        return (meanA - meanB) / denominator;
    }

    private static double Mean(double[] values)
    {
        double sum = 0;
        for (int i = 0; i < values.Length; i++)
            sum += values[i];
        return sum / values.Length;
    }

    private static double Variance(double[] values, double mean)
    {
        double sum = 0;
        for (int i = 0; i < values.Length; i++)
        {
            var diff = values[i] - mean;
            sum += diff * diff;
        }
        return sum / (values.Length - 1);
    }
}
