using System.Text;
using System.Text.Json;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// JSON / NDJSON extractor. Walks the DOM and emits every string value
/// (and every property name) on its own line so the classifier sees PII
/// regardless of how nested the document is. NDJSON is handled by parsing
/// each line as an independent root document.
/// </summary>
public sealed class StructuredJsonExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".json", ".ndjson" };
    public override string Format => "json";

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var raw = await ReadAllTextUtf8Async(stream, ct);
        var sb = new StringBuilder();
        bool isNdjson = fileName.EndsWith(".ndjson", StringComparison.OrdinalIgnoreCase);
        if (isNdjson)
        {
            foreach (var line in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0) continue;
                TryWalk(trimmed, sb);
            }
        }
        else
        {
            TryWalk(raw, sb);
        }
        return sb.ToString();
    }

    private static void TryWalk(string json, StringBuilder sb)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            Walk(doc.RootElement, sb);
        }
        catch (JsonException)
        {
            // Malformed line/document — fall back to raw text so the classifier still sees PII.
            sb.AppendLine(json);
        }
    }

    private static void Walk(JsonElement el, StringBuilder sb)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    sb.Append(prop.Name).Append(": ");
                    Walk(prop.Value, sb);
                    sb.AppendLine();
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray()) Walk(item, sb);
                break;
            case JsonValueKind.String:
                sb.Append(el.GetString()).Append(' ');
                break;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                sb.Append(el.ToString()).Append(' ');
                break;
        }
    }
}
