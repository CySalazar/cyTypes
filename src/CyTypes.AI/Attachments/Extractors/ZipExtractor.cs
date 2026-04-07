using System.IO.Compression;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>.zip extractor (stdlib System.IO.Compression).</summary>
public sealed class ZipExtractor : ArchiveExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".zip" };
    public override string Format => "zip";

    protected override IEnumerable<(string entryName, Stream entryStream)> EnumerateEntries(Stream stream)
    {
        var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        try
        {
            foreach (var entry in zip.Entries)
            {
                if (entry.Length == 0) continue; // directory entry
                yield return (entry.FullName, entry.Open());
            }
        }
        finally
        {
            zip.Dispose();
        }
    }
}
