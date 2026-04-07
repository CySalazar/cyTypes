using System.Text;
using UglyToad.PdfPig;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// PDF extractor — wraps UglyToad.PdfPig. Iterates pages and concatenates the
/// extracted text. Encrypted PDFs (with password) are not opened — the error
/// is captured by the base class and surfaced via <see cref="ExtractedContent.Error"/>.
/// </summary>
public sealed class PdfExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".pdf" };
    public override string Format => "pdf";

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        // Buffer to a byte[] because PdfPig reads from a Stream that must be seekable
        // and disposes via its own pipeline.
        byte[] bytes;
        if (stream is MemoryStream ms && ms.TryGetBuffer(out var seg))
            bytes = seg.AsSpan().ToArray();
        else
        {
            using var copy = new MemoryStream();
            stream.Position = 0;
            stream.CopyTo(copy);
            bytes = copy.ToArray();
        }

        using var doc = PdfDocument.Open(bytes);
        var sb = new StringBuilder();
        foreach (var page in doc.GetPages())
        {
            ct.ThrowIfCancellationRequested();
            var text = page.Text;
            if (!string.IsNullOrEmpty(text)) sb.AppendLine(text);
        }
        return Task.FromResult(sb.ToString());
    }
}
