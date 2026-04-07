using Avro.File;
using Avro.Generic;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Apache Avro extractor — opens the data file with a generic reader, walks
/// every record, and emits every field as a string.
/// </summary>
public sealed class AvroExtractor : AnalyticsExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".avro" };
    public override string Format => "avro";

    protected override IEnumerable<(string column, string value)> EnumerateColumnValues(Stream stream, string fileName, CancellationToken ct)
    {
        using var reader = DataFileReader<GenericRecord>.OpenReader(stream);
        while (reader.HasNext())
        {
            ct.ThrowIfCancellationRequested();
            var record = reader.Next();
            if (record is null) continue;
            foreach (var field in record.Schema.Fields)
            {
                if (!record.TryGetValue(field.Name, out var v) || v is null) continue;
                var s = v.ToString();
                if (!string.IsNullOrEmpty(s))
                    yield return (field.Name, s);
            }
        }
    }
}
