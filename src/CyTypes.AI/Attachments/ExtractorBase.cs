using System.Text;

namespace CyTypes.AI.Attachments;

/// <summary>
/// Common base for all built-in extractors. Concrete subclasses only need to
/// implement <see cref="ExtractTextAsync"/>; the base wraps any exception in an
/// <see cref="ExtractedContent"/> with a non-null <c>Error</c> field instead of
/// propagating, computes <c>FileSize</c>, and lets subclasses optionally produce
/// per-format metadata via <see cref="ExtractMetadataAsync"/>.
/// </summary>
public abstract class ExtractorBase : IAttachmentExtractor
{
    public abstract IReadOnlyList<string> SupportedExtensions { get; }
    public abstract string Format { get; }

    public async Task<ExtractedContent> ExtractAsync(Stream stream, string fileName, CancellationToken ct = default)
    {
        long size = stream.CanSeek ? stream.Length : -1;
        try
        {
            // Many extractors need to read the stream multiple times or seek
            // around. Buffer to memory if not already seekable.
            Stream working;
            MemoryStream? owned = null;
            if (stream.CanSeek)
            {
                working = stream;
                stream.Position = 0;
            }
            else
            {
                owned = new MemoryStream();
                await stream.CopyToAsync(owned, ct);
                size = owned.Length;
                owned.Position = 0;
                working = owned;
            }

            try
            {
                var text = await ExtractTextAsync(working, fileName, ct);
                var metadata = await ExtractMetadataAsync(working, fileName, ct);
                return new ExtractedContent(
                    FileName: fileName,
                    Format: Format,
                    Text: NormalizeText(text),
                    FileSize: size,
                    Error: null,
                    Metadata: metadata);
            }
            finally
            {
                owned?.Dispose();
            }
        }
        catch (Exception ex)
        {
            return new ExtractedContent(
                FileName: fileName,
                Format: Format,
                Text: string.Empty,
                FileSize: size,
                Error: $"{ex.GetType().Name}: {ex.Message}",
                Metadata: null);
        }
    }

    /// <summary>
    /// Subclass entry point: extract the textual content from <paramref name="stream"/>.
    /// </summary>
    protected abstract Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct);

    /// <summary>
    /// Optional subclass hook to return format-specific metadata
    /// (EXIF, ID3, OOXML core props, …). Default returns null.
    /// </summary>
    protected virtual Task<IReadOnlyDictionary<string, string>?> ExtractMetadataAsync(Stream stream, string fileName, CancellationToken ct)
        => Task.FromResult<IReadOnlyDictionary<string, string>?>(null);

    // ----- shared helpers -----

    /// <summary>Reads the whole stream as UTF-8 text.</summary>
    protected static async Task<string> ReadAllTextUtf8Async(Stream stream, CancellationToken ct)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        return await reader.ReadToEndAsync(ct);
    }

    /// <summary>Collapses runs of whitespace and trims, preserving newlines.</summary>
    protected static string NormalizeText(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var sb = new StringBuilder(text.Length);
        bool prevSpace = false;
        foreach (var c in text)
        {
            if (c == '\n' || c == '\r')
            {
                if (sb.Length > 0 && sb[^1] != '\n') sb.Append('\n');
                prevSpace = false;
                continue;
            }
            if (char.IsWhiteSpace(c))
            {
                if (!prevSpace && sb.Length > 0 && sb[^1] != '\n') { sb.Append(' '); prevSpace = true; }
                continue;
            }
            sb.Append(c);
            prevSpace = false;
        }
        return sb.ToString().Trim();
    }

    /// <summary>Helper for subclasses that need to format a key/value section into the text payload.</summary>
    protected static void AppendKeyValueSection(StringBuilder sb, string sectionName, IEnumerable<KeyValuePair<string, string>> pairs)
    {
        sb.AppendLine($"=== {sectionName} ===");
        foreach (var kv in pairs)
            if (!string.IsNullOrWhiteSpace(kv.Value))
                sb.AppendLine($"{kv.Key}: {kv.Value}");
        sb.AppendLine();
    }
}
