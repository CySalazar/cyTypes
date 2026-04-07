namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// SQL dump extractor — passes the file content through verbatim. INSERT
/// statements typically contain the actual data the classifier wants to scan.
/// </summary>
public sealed class SqlDumpExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".sql" };
    public override string Format => "sql";

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
        => ReadAllTextUtf8Async(stream, ct);
}
