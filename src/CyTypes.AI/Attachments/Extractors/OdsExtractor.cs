namespace CyTypes.AI.Attachments.Extractors;

/// <summary>OpenDocument Spreadsheet (.ods) extractor.</summary>
public sealed class OdsExtractor : OdfExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".ods" };
    public override string Format => "ods";
}
