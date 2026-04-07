using System.Text;
using System.Text.RegularExpressions;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// RTF extractor — strips control words and decodes <c>\\'XX</c> escape sequences.
/// Good enough to recover the visible text, not a full RTF parser.
/// </summary>
public sealed class RtfExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".rtf" };
    public override string Format => "rtf";

    private static readonly Regex _controlWord = new(@"\\[a-zA-Z]+-?\d*\s?", RegexOptions.Compiled);
    private static readonly Regex _hexEscape = new(@"\\'([0-9a-fA-F]{2})", RegexOptions.Compiled);
    private static readonly Regex _braces = new(@"[{}]", RegexOptions.Compiled);

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var raw = await ReadAllTextUtf8Async(stream, ct);
        // 1) decode \\'XX hex escapes (windows-1252 default)
        var decoded = _hexEscape.Replace(raw, m =>
        {
            var b = Convert.ToByte(m.Groups[1].Value, 16);
            return Encoding.GetEncoding("windows-1252").GetString(new[] { b });
        });
        // 2) strip control words
        decoded = _controlWord.Replace(decoded, " ");
        // 3) strip braces
        decoded = _braces.Replace(decoded, " ");
        return decoded;
    }
}
