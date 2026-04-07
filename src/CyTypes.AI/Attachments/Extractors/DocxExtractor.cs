using System.IO.Compression;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .docx text extractor — pulls every <c>w:t</c> element out of <c>word/document.xml</c>.
/// </summary>
public sealed class DocxExtractor : OoxmlExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".docx" };
    public override string Format => "docx";

    protected override IEnumerable<string> ExtractTextFromZip(ZipArchive zip)
    {
        var doc = LoadXml(Find(zip, "word/document.xml"));
        return ElementsByLocalName(doc, "t");
    }
}
