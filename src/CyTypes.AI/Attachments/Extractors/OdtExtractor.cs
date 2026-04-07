namespace CyTypes.AI.Attachments.Extractors;

/// <summary>OpenDocument Text (.odt) extractor.</summary>
public sealed class OdtExtractor : OdfExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".odt" };
    public override string Format => "odt";
}
