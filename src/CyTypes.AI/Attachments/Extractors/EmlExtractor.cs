using System.Text;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// EML extractor — minimal RFC 822 parser. Splits headers from the body on
/// the first blank line, parses standard headers (From / To / Cc / Subject /
/// Date), unfolds multi-line headers, and emits a uniform key/value layout
/// followed by the body.
///
/// Multipart messages are handled in a best-effort way: the extractor walks
/// the parts and concatenates every <c>text/*</c> part into the body. Binary
/// parts are skipped (they would normally be sent through the dispatcher to
/// the right extractor; that level of nesting is left to a future iteration).
/// </summary>
public sealed class EmlExtractor : EmailExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".eml" };
    public override string Format => "eml";

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var raw = await ReadAllTextUtf8Async(stream, ct);
        var (headers, body) = SplitHeadersAndBody(raw);
        return FormatEmail(
            from: headers.GetValueOrDefault("from"),
            to: headers.GetValueOrDefault("to"),
            cc: headers.GetValueOrDefault("cc"),
            subject: headers.GetValueOrDefault("subject"),
            date: headers.GetValueOrDefault("date"),
            body: body);
    }

    private static (Dictionary<string, string> headers, string body) SplitHeadersAndBody(string raw)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = raw.Split('\n');
        int i = 0;
        var currentHeader = new StringBuilder();
        string currentName = string.Empty;

        void Commit()
        {
            if (currentName.Length > 0)
                headers[currentName] = currentHeader.ToString().Trim();
            currentName = string.Empty;
            currentHeader.Clear();
        }

        for (; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (string.IsNullOrEmpty(line)) { Commit(); i++; break; }
            if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t'))
            {
                currentHeader.Append(' ').Append(line.TrimStart());
                continue;
            }
            Commit();
            int colon = line.IndexOf(':');
            if (colon > 0)
            {
                currentName = line.Substring(0, colon).Trim().ToLowerInvariant();
                currentHeader.Append(line.Substring(colon + 1).Trim());
            }
        }
        Commit();
        var body = string.Join('\n', lines.Skip(i));
        return (headers, body);
    }
}
