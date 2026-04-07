namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Standard raster image extractor — JPEG, PNG, GIF, BMP, TIFF, WebP.
/// Inherits the metadata + OCR pipeline from <see cref="ImageExtractorBase"/>;
/// the bytes are passed through unchanged because Tesseract supports all of
/// these formats natively via libleptonica.
/// </summary>
public sealed class StandardImageExtractor : ImageExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[]
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp"
    };

    public override string Format => "image";
}
