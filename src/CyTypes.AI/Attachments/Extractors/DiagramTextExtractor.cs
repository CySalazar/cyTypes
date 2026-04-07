namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Plain-text diagram source extractor — Mermaid (.mmd), PlantUML (.plantuml/.puml).
/// They are just text files but kept as a separate extractor so the dispatcher
/// reports a meaningful <see cref="Format"/>.
/// </summary>
public sealed class DiagramTextExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".mmd", ".plantuml", ".puml" };
    public override string Format => "diagram-source";

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
        => ReadAllTextUtf8Async(stream, ct);
}
