using Parquet;
using Parquet.Schema;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Apache Parquet extractor — reads every row group, every column, and emits
/// every cell value via the <see cref="AnalyticsExtractorBase"/> formatter.
/// </summary>
public sealed class ParquetExtractor : AnalyticsExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".parquet" };
    public override string Format => "parquet";

    protected override IEnumerable<(string column, string value)> EnumerateColumnValues(Stream stream, string fileName, CancellationToken ct)
    {
        // The async API would be cleaner but yield-return forbids `await`. Block here.
        var reader = ParquetReader.CreateAsync(stream).GetAwaiter().GetResult();
        try
        {
            for (int rg = 0; rg < reader.RowGroupCount; rg++)
            {
                ct.ThrowIfCancellationRequested();
                using var rgReader = reader.OpenRowGroupReader(rg);
                foreach (var field in reader.Schema.GetDataFields())
                {
                    var col = rgReader.ReadColumnAsync(field).GetAwaiter().GetResult();
                    if (col?.Data is null) continue;
                    foreach (var item in col.Data)
                    {
                        if (item is null) continue;
                        var s = item.ToString();
                        if (!string.IsNullOrEmpty(s))
                            yield return (field.Name, s);
                    }
                }
            }
        }
        finally
        {
            reader.Dispose();
        }
    }
}
