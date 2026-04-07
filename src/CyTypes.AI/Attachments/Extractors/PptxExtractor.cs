using System.IO.Compression;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .pptx extractor — pulls every <c>a:t</c> element from <c>ppt/slides/slide*.xml</c>.
/// </summary>
public sealed class PptxExtractor : OoxmlExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".pptx" };
    public override string Format => "pptx";

    protected override IEnumerable<string> ExtractTextFromZip(ZipArchive zip)
    {
        foreach (var entry in zip.Entries
            .Where(e => e.FullName.StartsWith("ppt/slides/slide", StringComparison.OrdinalIgnoreCase)
                     && e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)))
        {
            var doc = LoadXml(entry);
            foreach (var t in ElementsByLocalName(doc, "t")) yield return t;
        }
    }
}
