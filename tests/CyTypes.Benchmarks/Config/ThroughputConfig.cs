using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;

namespace CyTypes.Benchmarks.Config;

public class ThroughputConfig : ManualConfig
{
    public ThroughputConfig()
    {
        AddColumn(StatisticColumn.OperationsPerSecond);
        AddColumn(new ThroughputColumn());
        WithSummaryStyle(SummaryStyle.Default.WithRatioStyle(RatioStyle.Trend));
    }
}

public class ThroughputColumn : IColumn
{
    public string Id => "MB/s";
    public string ColumnName => "MB/s";
    public bool AlwaysShow => true;
    public ColumnCategory Category => ColumnCategory.Custom;
    public int PriorityInCategory => 0;
    public bool IsNumeric => true;
    public UnitType UnitType => UnitType.Dimensionless;
    public string Legend => "Throughput in MB/s";

    public string GetValue(Summary summary, BenchmarkCase benchmarkCase)
    {
        return GetValue(summary, benchmarkCase, SummaryStyle.Default);
    }

    public string GetValue(Summary summary, BenchmarkCase benchmarkCase, SummaryStyle style)
    {
        var report = summary[benchmarkCase];
        if (report?.ResultStatistics == null)
            return "N/A";

        var payloadParam = benchmarkCase.Parameters["PayloadSize"];
        if (payloadParam == null)
            return "N/A";

        var payloadSize = (int)payloadParam;
        var nsPerOp = report.ResultStatistics.Mean;
        var opsPerSec = 1_000_000_000.0 / nsPerOp;
        var mbPerSec = (opsPerSec * payloadSize) / (1024.0 * 1024.0);

        return mbPerSec.ToString("F2", System.Globalization.CultureInfo.InvariantCulture);
    }

    public bool IsDefault(Summary summary, BenchmarkCase benchmarkCase) => false;
    public bool IsAvailable(Summary summary) => true;
}
