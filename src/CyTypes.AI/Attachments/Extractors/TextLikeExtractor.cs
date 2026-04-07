namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Generic UTF-8 plain-text reader. Handles any extension where the file IS
/// just text the user wrote (txt/log/md/csv/tsv/sql/ini/conf/env/yaml/yml +
/// the diagram-source extensions handled by <see cref="DiagramTextExtractor"/>
/// are kept here too for convenience).
/// </summary>
public sealed class TextLikeExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[]
    {
        ".txt", ".log", ".md",
        ".csv", ".tsv",
        ".ini", ".conf", ".env",
        ".yaml", ".yml",
    };

    public override string Format => "text";

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
        => ReadAllTextUtf8Async(stream, ct);
}
