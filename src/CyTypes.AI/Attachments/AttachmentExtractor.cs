using CyTypes.AI.Attachments.Extractors;

namespace CyTypes.AI.Attachments;

/// <summary>
/// Static dispatcher: looks up the right <see cref="IAttachmentExtractor"/> by file extension
/// and routes the call. New extractors (third-party, company-custom) can be plugged in via
/// <see cref="RegisterExtractor"/>.
/// </summary>
public static class AttachmentExtractor
{
    private static readonly Dictionary<string, IAttachmentExtractor> _byExtension =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly List<IAttachmentExtractor> _registered = new();

    static AttachmentExtractor()
    {
        // Wave 1 — text-based extractors
        RegisterExtractor(new TextLikeExtractor());
        RegisterExtractor(new StructuredJsonExtractor());
        RegisterExtractor(new StructuredXmlExtractor());
        RegisterExtractor(new HtmlExtractor());
        RegisterExtractor(new RtfExtractor());
        RegisterExtractor(new DiagramTextExtractor());
        RegisterExtractor(new SqlDumpExtractor());
        RegisterExtractor(new EmlExtractor());
        // Wave 2 — Office, PDF, heavy email, database, analytics
        RegisterExtractor(new DocxExtractor());
        RegisterExtractor(new XlsxExtractor());
        RegisterExtractor(new PptxExtractor());
        RegisterExtractor(new VsdxExtractor());
        RegisterExtractor(new OdtExtractor());
        RegisterExtractor(new OdsExtractor());
        RegisterExtractor(new OdpExtractor());
        RegisterExtractor(new PdfExtractor());
        RegisterExtractor(new MsgExtractor());
        RegisterExtractor(new XstExtractor());
        RegisterExtractor(new SqliteExtractor());
        RegisterExtractor(new MdbExtractor());
        RegisterExtractor(new ParquetExtractor());
        RegisterExtractor(new AvroExtractor());
        // Wave 3 — archives
        RegisterExtractor(new ZipExtractor());
        RegisterExtractor(new TarExtractor());
        RegisterExtractor(new GzipExtractor());
        RegisterExtractor(new RarExtractor());
        RegisterExtractor(new SevenZipExtractor());
        // Wave 4 — image metadata + OCR
        RegisterExtractor(new StandardImageExtractor());
        RegisterExtractor(new HeifImageExtractor());
        // Wave 5 — audio metadata + STT
        RegisterExtractor(new AudioFileExtractor());
        // Wave 6 — video + legacy Visio
        RegisterExtractor(new VideoFileExtractor());
        RegisterExtractor(new LegacyVisioExtractor());
    }

    /// <summary>Adds (or replaces) an extractor in the dispatcher registry.</summary>
    public static void RegisterExtractor(IAttachmentExtractor extractor)
    {
        _registered.Add(extractor);
        foreach (var ext in extractor.SupportedExtensions)
        {
            var key = ext.StartsWith('.') ? ext : "." + ext;
            _byExtension[key.ToLowerInvariant()] = extractor;
        }
    }

    public static IReadOnlyList<string> SupportedExtensions => _byExtension.Keys.OrderBy(x => x).ToList();
    public static IReadOnlyList<IAttachmentExtractor> Extractors => _registered;

    public static IAttachmentExtractor? GetExtractor(string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        return _byExtension.TryGetValue(ext, out var e) ? e : null;
    }

    public static async Task<ExtractedContent> ExtractAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
            return new ExtractedContent(Path.GetFileName(filePath), "unknown", string.Empty, 0,
                Error: $"file not found: {filePath}");
        await using var fs = File.OpenRead(filePath);
        return await ExtractAsync(fs, Path.GetFileName(filePath), ct);
    }

    public static async Task<ExtractedContent> ExtractAsync(Stream stream, string fileName, CancellationToken ct = default)
    {
        var extractor = GetExtractor(fileName);
        if (extractor is null)
            return new ExtractedContent(fileName, "unknown", string.Empty, stream.CanSeek ? stream.Length : -1,
                Error: $"no extractor registered for extension {Path.GetExtension(fileName)}");
        return await extractor.ExtractAsync(stream, fileName, ct);
    }
}
