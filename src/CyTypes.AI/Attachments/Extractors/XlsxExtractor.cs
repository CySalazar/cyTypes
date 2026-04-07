using System.IO.Compression;
using System.Xml.Linq;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .xlsx text extractor — concatenates the shared strings table plus all
/// inline string and number cells across every worksheet.
/// </summary>
public sealed class XlsxExtractor : OoxmlExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".xlsx" };
    public override string Format => "xlsx";

    protected override IEnumerable<string> ExtractTextFromZip(ZipArchive zip)
    {
        // 1) shared strings (xl/sharedStrings.xml) — used by most XLSX writers
        var ss = LoadXml(Find(zip, "xl/sharedStrings.xml"));
        foreach (var t in ElementsByLocalName(ss, "t")) yield return t;

        // 2) every sheet — inline strings (<is><t>...</t></is>) and number cell values
        foreach (var entry in zip.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/sheet", StringComparison.OrdinalIgnoreCase)))
        {
            var sheet = LoadXml(entry);
            if (sheet?.Root is null) continue;
            foreach (var c in sheet.Root.Descendants().Where(e => e.Name.LocalName == "c"))
            {
                var t = c.Attribute("t")?.Value;
                if (t == "inlineStr")
                {
                    foreach (var inlineT in c.Descendants().Where(e => e.Name.LocalName == "t"))
                        yield return inlineT.Value;
                }
                else if (t != "s")  // skip shared-string refs (already in step 1) but emit raw values
                {
                    var v = c.Descendants().FirstOrDefault(e => e.Name.LocalName == "v")?.Value;
                    if (!string.IsNullOrEmpty(v)) yield return v;
                }
            }
        }
    }
}
