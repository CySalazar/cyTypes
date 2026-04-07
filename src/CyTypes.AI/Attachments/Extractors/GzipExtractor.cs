using System.IO.Compression;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .gz extractor (stdlib GZipStream). A gzip file is a single compressed
/// stream, not a multi-entry archive: the extractor decompresses to memory
/// and dispatches the result to the right extractor based on the inner
/// filename (e.g. <c>foo.tar.gz</c> → tar; <c>foo.json.gz</c> → json;
/// <c>foo.gz</c> with no inner extension → text fallback).
/// </summary>
public sealed class GzipExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".gz" };
    public override string Format => "gzip";

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        // Strip the trailing .gz to get the inner filename
        var innerName = fileName;
        if (innerName.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            innerName = innerName.Substring(0, innerName.Length - 3);
        if (innerName.Length == 0 || Path.GetExtension(innerName).Length == 0)
            innerName += ".txt";

        await using var gz = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
        using var ms = new MemoryStream();
        await gz.CopyToAsync(ms, ct);
        ms.Position = 0;
        var inner = await AttachmentExtractor.ExtractAsync(ms, innerName, ct);
        return inner.HasError
            ? $"=== gzip {fileName} ===\n[inner extractor error: {inner.Error}]"
            : $"=== gzip {fileName} → {innerName} ===\n{inner.Text}";
    }
}
