using System.Text;
using MetadataExtractor;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for image extractors. Implements two phases:
///   1. <b>Metadata</b> via MetadataExtractor.NET — EXIF, IPTC, XMP, GPS,
///      UserComment. Always runs.
///   2. <b>OCR</b> via Tesseract (libtesseract) — extracts visible text from
///      the rendered pixels. Optional: turned on by default but skipped if
///      the native Tesseract runtime can't be loaded (the extractor still
///      returns the metadata-only text in that case).
///
/// Subclasses may override <see cref="LoadImageBytesAsync"/> to convert
/// non-standard formats (e.g. HEIC via Magick.NET) into bytes that Tesseract
/// can ingest directly.
/// </summary>
public abstract class ImageExtractorBase : ExtractorBase
{
    /// <summary>Default true. Set to false to disable OCR globally.</summary>
    public static bool OcrEnabled { get; set; } = true;
    public static string OcrLanguages { get; set; } = "eng+ita";

    private static bool? _ocrAvailable;
    private static readonly object _ocrLock = new();

    /// <summary>
    /// Subclasses can override to transform the input bytes (e.g. HEIC → PNG)
    /// before they reach Tesseract. Default returns the bytes unchanged.
    /// </summary>
    protected virtual Task<byte[]> LoadImageBytesAsync(Stream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        stream.Position = 0;
        stream.CopyTo(ms);
        return Task.FromResult(ms.ToArray());
    }

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var bytes = await LoadImageBytesAsync(stream, ct);
        var sb = new StringBuilder();

        // ---- Phase 1: metadata ----
        sb.AppendLine($"=== Image: {fileName} ===");
        try
        {
            using var ms = new MemoryStream(bytes, writable: false);
            var directories = ImageMetadataReader.ReadMetadata(ms);
            foreach (var dir in directories)
            {
                foreach (var tag in dir.Tags)
                {
                    if (string.IsNullOrWhiteSpace(tag.Description)) continue;
                    sb.Append(dir.Name).Append('/').Append(tag.Name).Append(": ").AppendLine(tag.Description);
                }
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine($"(metadata extraction failed: {ex.Message})");
        }

        // ---- Phase 2: OCR ----
        if (OcrEnabled && IsOcrAvailable())
        {
            try
            {
                var tessdataDir = TessdataDownloader.EnsureLanguages();
                var ocrText = RunTesseract(bytes, tessdataDir);
                if (!string.IsNullOrWhiteSpace(ocrText))
                {
                    sb.AppendLine();
                    sb.AppendLine("=== OCR text ===");
                    sb.AppendLine(ocrText.Trim());
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"(OCR failed: {ex.Message})");
            }
        }

        return sb.ToString();
    }

    private static bool IsOcrAvailable()
    {
        if (_ocrAvailable is bool b) return b;
        lock (_ocrLock)
        {
            if (_ocrAvailable is bool bb) return bb;
            try
            {
                // Probe libtesseract by attempting to construct a tiny engine.
                // We need the language data first; if missing, the probe still
                // works because we use the cache dir which gets populated lazily.
                var dir = TessdataDownloader.EnsureLanguages(new[] { "eng" });
                using var engine = new global::Tesseract.TesseractEngine(dir, "eng", global::Tesseract.EngineMode.Default);
                _ocrAvailable = true;
            }
            catch
            {
                _ocrAvailable = false;
            }
            return _ocrAvailable.Value;
        }
    }

    private static string RunTesseract(byte[] bytes, string tessdataDir)
    {
        // Try requested languages, fall back to "eng" if some are missing.
        string langs = OcrLanguages;
        global::Tesseract.TesseractEngine engine;
        try
        {
            engine = new global::Tesseract.TesseractEngine(tessdataDir, langs, global::Tesseract.EngineMode.Default);
        }
        catch
        {
            engine = new global::Tesseract.TesseractEngine(tessdataDir, "eng", global::Tesseract.EngineMode.Default);
        }
        try
        {
            using var pix = global::Tesseract.Pix.LoadFromMemory(bytes);
            using var page = engine.Process(pix);
            return page.GetText();
        }
        finally
        {
            engine.Dispose();
        }
    }
}
