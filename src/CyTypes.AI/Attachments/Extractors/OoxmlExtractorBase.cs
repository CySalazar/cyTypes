using System.IO.Compression;
using System.Text;
using System.Xml.Linq;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for Office Open XML extractors (DOCX/XLSX/PPTX/VSDX). All four
/// formats are ZIP archives whose payload is a set of XML parts. Subclasses
/// override <see cref="ExtractTextFromZip"/> to know which parts to read and
/// which XML elements carry the human-visible text.
/// </summary>
public abstract class OoxmlExtractorBase : ExtractorBase
{
    /// <summary>
    /// Subclasses iterate through <paramref name="zip"/> and yield human-visible
    /// text snippets in document order.
    /// </summary>
    protected abstract IEnumerable<string> ExtractTextFromZip(ZipArchive zip);

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        var sb = new StringBuilder();
        foreach (var snippet in ExtractTextFromZip(zip))
        {
            if (string.IsNullOrEmpty(snippet)) continue;
            sb.AppendLine(snippet);
        }
        return Task.FromResult(sb.ToString());
    }

    /// <summary>Open a zip entry by full path; returns null if missing.</summary>
    protected static ZipArchiveEntry? Find(ZipArchive zip, string path) =>
        zip.Entries.FirstOrDefault(e => string.Equals(e.FullName, path, StringComparison.OrdinalIgnoreCase));

    /// <summary>Read a zip entry as a parsed XDocument; returns null if missing or malformed.</summary>
    protected static XDocument? LoadXml(ZipArchiveEntry? entry)
    {
        if (entry is null) return null;
        try
        {
            using var s = entry.Open();
            return XDocument.Load(s);
        }
        catch (System.Xml.XmlException) { return null; }
    }

    /// <summary>Yields the text content of every element with the given local name (any namespace).</summary>
    protected static IEnumerable<string> ElementsByLocalName(XDocument? doc, string localName)
    {
        if (doc?.Root is null) yield break;
        foreach (var el in doc.Root.Descendants().Where(e => e.Name.LocalName == localName))
        {
            var v = el.Value;
            if (!string.IsNullOrEmpty(v)) yield return v;
        }
    }
}
