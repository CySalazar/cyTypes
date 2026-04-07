namespace CyTypes.AI.Attachments;

/// <summary>
/// Result of extracting plain text from an attachment. <see cref="Text"/> is the
/// concatenated content (metadata + body + nested attachments) ready to be passed
/// to a classifier. <see cref="Error"/> is non-null only when extraction failed;
/// in that case <see cref="Text"/> is the empty string.
/// </summary>
public sealed record ExtractedContent(
    string FileName,
    string Format,
    string Text,
    long FileSize,
    string? Error = null,
    IReadOnlyDictionary<string, string>? Metadata = null)
{
    public bool HasError => Error is not null;
    public int TextLength => Text.Length;
}
