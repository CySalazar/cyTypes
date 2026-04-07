using System.IO.Compression;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .vsdx (modern Visio) extractor — Visio shapes carry their visible text in
/// <c>visio/pages/page*.xml</c> as <c>&lt;Text&gt;</c> elements.
/// </summary>
public sealed class VsdxExtractor : OoxmlExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".vsdx" };
    public override string Format => "vsdx";

    protected override IEnumerable<string> ExtractTextFromZip(ZipArchive zip)
    {
        foreach (var entry in zip.Entries
            .Where(e => e.FullName.StartsWith("visio/pages/", StringComparison.OrdinalIgnoreCase)
                     && e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)))
        {
            var doc = LoadXml(entry);
            foreach (var t in ElementsByLocalName(doc, "Text")) yield return t;
        }
    }
}
