using SharpCompress.Archives.Rar;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>.rar extractor — uses SharpCompress (read-only for RAR).</summary>
public sealed class RarExtractor : ArchiveExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".rar" };
    public override string Format => "rar";

    protected override IEnumerable<(string entryName, Stream entryStream)> EnumerateEntries(Stream stream)
    {
        var archive = RarArchive.OpenArchive(stream);
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
