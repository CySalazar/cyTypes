using ImageMagick;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// HEIC / HEIF image extractor — uses Magick.NET to decode the HEIF container
/// (libheif backend bundled with the Magick.NET native runtime) into a PNG
/// in memory, then routes to the standard <see cref="ImageExtractorBase"/>
/// pipeline (metadata + Tesseract OCR).
/// </summary>
public sealed class HeifImageExtractor : ImageExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".heic", ".heif" };
    public override string Format => "heif";

    protected override Task<byte[]> LoadImageBytesAsync(Stream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        stream.Position = 0;
        stream.CopyTo(ms);
        ms.Position = 0;
        try
        {
            using var image = new MagickImage(ms);
            image.Format = MagickFormat.Png;
            using var output = new MemoryStream();
            image.Write(output);
            return Task.FromResult(output.ToArray());
        }
        catch (MagickException ex)
        {
            throw new InvalidOperationException(
                $"HEIF decode failed (Magick.NET native runtime missing libheif?): {ex.Message}", ex);
        }
    }
}
