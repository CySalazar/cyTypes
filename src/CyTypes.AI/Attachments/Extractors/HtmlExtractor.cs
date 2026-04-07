using System.Net;
using System.Text.RegularExpressions;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// HTML extractor — strips tags, decodes entities, drops &lt;script&gt;/&lt;style&gt; bodies.
/// </summary>
public sealed class HtmlExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".html", ".htm" };
    public override string Format => "html";

    private static readonly Regex _scriptStyle = new(@"<(script|style)[^>]*>.*?</\1\s*>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex _tag = new(@"<[^>]+>", RegexOptions.Compiled);
    private static readonly Regex _ws = new(@"\s+", RegexOptions.Compiled);

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var raw = await ReadAllTextUtf8Async(stream, ct);
        var noScripts = _scriptStyle.Replace(raw, " ");
        var noTags = _tag.Replace(noScripts, " ");
        var decoded = WebUtility.HtmlDecode(noTags);
        return _ws.Replace(decoded, " ").Trim();
    }
}
