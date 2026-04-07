using SharpCompress.Archives.SevenZip;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>.7z extractor — uses SharpCompress.</summary>
public sealed class SevenZipExtractor : ArchiveExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".7z" };
    public override string Format => "7z";

    protected override IEnumerable<(string entryName, Stream entryStream)> EnumerateEntries(Stream stream)
    {
        var archive = SevenZipArchive.OpenArchive(stream);
        try
        {
            foreach (var entry in archive.Entries)
            {
                if (entry.IsDirectory || entry.Size == 0) continue;
                yield return (entry.Key ?? "(unnamed)", entry.OpenEntryStream());
            }
        }
        finally
        {
            archive.Dispose();
        }
    }
}
