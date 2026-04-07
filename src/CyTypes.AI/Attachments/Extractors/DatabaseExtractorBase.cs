using System.Text;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for database extractors. Subclasses enumerate <c>(table, column, value)</c>
/// triples; the base formats them as a uniform key-value section so the classifier
/// sees PII regardless of source database engine.
/// </summary>
public abstract class DatabaseExtractorBase : ExtractorBase
{
    protected abstract IEnumerable<(string table, string column, string value)> EnumerateStringValues(Stream stream, string fileName, CancellationToken ct);

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== Database content: {fileName} ===");
        string? lastTable = null;
        foreach (var (table, column, value) in EnumerateStringValues(stream, fileName, ct))
        {
            if (lastTable != table)
            {
                sb.AppendLine();
                sb.Append("[table ").Append(table).AppendLine("]");
                lastTable = table;
            }
            if (!string.IsNullOrEmpty(value))
                sb.Append(column).Append(": ").AppendLine(value);
        }
        return Task.FromResult(sb.ToString());
    }
}
