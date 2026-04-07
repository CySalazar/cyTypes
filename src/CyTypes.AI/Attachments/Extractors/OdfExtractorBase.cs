using System.IO.Compression;
using System.Text;
using System.Xml.Linq;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for OpenDocument Format extractors (ODT/ODS/ODP). All three are
/// ZIP archives whose human-visible text lives in <c>content.xml</c>. Subclasses
/// only declare which extension they handle and the format identifier.
/// </summary>
public abstract class OdfExtractorBase : ExtractorBase
{
    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        var entry = zip.Entries.FirstOrDefault(e => string.Equals(e.FullName, "content.xml", StringComparison.OrdinalIgnoreCase));
        if (entry is null) return Task.FromResult(string.Empty);
        using var s = entry.Open();
        XDocument doc;
        try { doc = XDocument.Load(s); }
        catch (System.Xml.XmlException) { return Task.FromResult(string.Empty); }

        var sb = new StringBuilder();
        foreach (var node in doc.Descendants())
        {
            // ODF wraps every text run in <text:p>, <text:span>, <text:h>, etc.
            // The local-name is always one of: "p", "h", "span", "a", "list-item", ...
            // We just walk every element with leaf text content and append it.
            var local = node.Name.LocalName;
            if (local is "p" or "h" or "span" or "list-item" or "table-cell")
            {
                var text = node.Value;
                if (!string.IsNullOrWhiteSpace(text)) sb.AppendLine(text);
            }
        }
        return Task.FromResult(sb.ToString());
    }
}
