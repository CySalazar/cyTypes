namespace CyTypes.AI.Attachments.Extractors;

/// <summary>OpenDocument Presentation (.odp) extractor.</summary>
public sealed class OdpExtractor : OdfExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".odp" };
    public override string Format => "odp";
}
