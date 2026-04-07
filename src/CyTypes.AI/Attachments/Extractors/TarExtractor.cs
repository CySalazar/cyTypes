using System.Formats.Tar;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>.tar extractor (stdlib System.Formats.Tar).</summary>
public sealed class TarExtractor : ArchiveExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".tar" };
    public override string Format => "tar";

    protected override IEnumerable<(string entryName, Stream entryStream)> EnumerateEntries(Stream stream)
    {
        var reader = new TarReader(stream, leaveOpen: true);
        try
        {
            TarEntry? entry;
            while ((entry = reader.GetNextEntry(copyData: true)) is not null)
            {
                if (entry.EntryType is TarEntryType.Directory) continue;
                if (entry.DataStream is null) continue;
                yield return (entry.Name, entry.DataStream);
            }
        }
        finally
        {
            reader.Dispose();
        }
    }
}
