using System.Text;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for analytics columnar formats (Parquet/Avro). Subclasses
/// enumerate <c>(column, value)</c> pairs; the base wraps them in a uniform
/// section header so the classifier sees PII independently of the source format.
/// </summary>
public abstract class AnalyticsExtractorBase : ExtractorBase
{
    protected abstract IEnumerable<(string column, string value)> EnumerateColumnValues(Stream stream, string fileName, CancellationToken ct);

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append("=== Columnar dataset: ").Append(fileName).AppendLine(" ===");
        foreach (var (col, val) in EnumerateColumnValues(stream, fileName, ct))
        {
            if (string.IsNullOrEmpty(val)) continue;
            sb.Append(col).Append(": ").AppendLine(val);
        }
        return Task.FromResult(sb.ToString());
    }
}
