using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// HTML extractor — strips tags, decodes entities, drops &lt;script&gt;/&lt;style&gt; bodies.
///
/// Before stripping the markup the extractor harvests the values of attributes
/// that commonly carry PII or URLs (<c>href</c>, <c>src</c>, <c>action</c>,
/// <c>data-*</c>, <c>value</c>, <c>placeholder</c>, <c>alt</c>, <c>title</c>,
/// <c>content</c>) and appends them to the body so the downstream classifier
/// sees emails buried in <c>&lt;a href="mailto:..."&gt;</c>, links pointing to
/// internal IPs, etc.
/// </summary>
public sealed class HtmlExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".html", ".htm" };
    public override string Format => "html";

    private static readonly Regex _scriptStyle = new(@"<(script|style)[^>]*>.*?</\1\s*>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex _tag = new(@"<[^>]+>", RegexOptions.Compiled);
    private static readonly Regex _ws = new(@"\s+", RegexOptions.Compiled);

    // Match every attribute = "value" / 'value' / value pair where the
    // attribute name is one of the PII-relevant keys.
    private static readonly Regex _attrs = new(
        @"(?:href|src|action|value|placeholder|alt|title|content|data-[a-zA-Z0-9_-]+)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var raw = await ReadAllTextUtf8Async(stream, ct);

        // 1) harvest attribute values BEFORE stripping tags
        var harvested = new StringBuilder();
        foreach (Match m in _attrs.Matches(raw))
        {
            var v = m.Groups[1].Success ? m.Groups[1].Value
                  : m.Groups[2].Success ? m.Groups[2].Value
                  : m.Groups[3].Value;
            if (string.IsNullOrWhiteSpace(v)) continue;
            // Strip "mailto:" / "tel:" prefixes so the downstream classifier
            // sees a clean email/phone token.
            if (v.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) v = v.Substring(7);
            else if (v.StartsWith("tel:", StringComparison.OrdinalIgnoreCase)) v = v.Substring(4);
            harvested.Append(v).Append(' ');
        }

        // 2) strip script/style + tags + decode entities
        var noScripts = _scriptStyle.Replace(raw, " ");
        var noTags = _tag.Replace(noScripts, " ");
        var decoded = WebUtility.HtmlDecode(noTags);

        // 3) concat body + harvested attribute values
        var combined = decoded + " " + harvested;
        return _ws.Replace(combined, " ").Trim();
    }
}
