namespace CyTypes.AI.Attachments;

/// <summary>
/// Contract for any extractor that can convert a binary or text file into a
/// flat string of plain text suitable for being passed to a
/// <see cref="CyTypes.AI.Classification.DataClassifier"/>.
/// </summary>
public interface IAttachmentExtractor
{
    /// <summary>
    /// File extensions handled by this extractor, lowercase, with leading dot
    /// (e.g. <c>".pdf"</c>, <c>".docx"</c>). Used by the dispatcher to map
    /// incoming files to extractors.
    /// </summary>
    IReadOnlyList<string> SupportedExtensions { get; }

    /// <summary>
    /// Canonical short identifier for the format (e.g. "pdf", "docx", "msg").
    /// Surfaced in <see cref="ExtractedContent.Format"/>.
    /// </summary>
    string Format { get; }

    /// <summary>
    /// Reads <paramref name="stream"/> and returns the extracted text content.
    /// Implementations should never throw on extraction errors — wrap them in
    /// the returned <see cref="ExtractedContent.Error"/> field instead.
    /// </summary>
    Task<ExtractedContent> ExtractAsync(Stream stream, string fileName, CancellationToken ct = default);
}
