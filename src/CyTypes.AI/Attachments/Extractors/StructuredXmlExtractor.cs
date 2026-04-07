using System.Text;
using System.Xml.Linq;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// XML extractor — walks every element / attribute and emits all the text
/// content. Used for plain .xml plus diagram-source variants like .drawio
/// (a draw.io / diagrams.net document is just XML).
/// </summary>
public sealed class StructuredXmlExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".xml", ".drawio" };
    public override string Format => "xml";

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var raw = await ReadAllTextUtf8Async(stream, ct);
        var sb = new StringBuilder();
        try
        {
            var doc = XDocument.Parse(raw);
            if (doc.Root is not null) Walk(doc.Root, sb);
        }
        catch (System.Xml.XmlException)
        {
            sb.Append(raw);
        }
        return sb.ToString();
    }

    private static void Walk(XElement el, StringBuilder sb)
    {
        sb.Append(el.Name.LocalName).Append(": ");
        foreach (var attr in el.Attributes())
            sb.Append(attr.Name.LocalName).Append('=').Append(attr.Value).Append(' ');
        foreach (var node in el.Nodes())
        {
            if (node is XText t) sb.Append(t.Value).Append(' ');
        }
        sb.AppendLine();
        foreach (var child in el.Elements())
            Walk(child, sb);
    }
}
