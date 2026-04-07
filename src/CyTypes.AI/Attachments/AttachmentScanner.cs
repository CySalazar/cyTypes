using CyTypes.AI.Classification;

namespace CyTypes.AI.Attachments;

/// <summary>
/// High-level helper that extracts text from an attachment and runs it through
/// a <see cref="DataClassifier"/> in one call. The classifier's plugin chain
/// (built-in compliance + any custom plugin like AcmeInternalPlugin) is applied
/// to every attachment uniformly, regardless of source format.
/// </summary>
public sealed class AttachmentScanner
{
    private readonly DataClassifier _classifier;

    public AttachmentScanner(DataClassifier classifier)
    {
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
    }

    public async Task<AttachmentScanResult> ScanFileAsync(string filePath, CancellationToken ct = default)
    {
        var content = await AttachmentExtractor.ExtractAsync(filePath, ct);
        return Classify(content);
    }

    public async Task<AttachmentScanResult> ScanStreamAsync(Stream stream, string fileName, CancellationToken ct = default)
    {
        var content = await AttachmentExtractor.ExtractAsync(stream, fileName, ct);
        return Classify(content);
    }

    public async Task<IReadOnlyList<AttachmentScanResult>> ScanDirectoryAsync(string dir, bool recursive = true, CancellationToken ct = default)
    {
        if (!Directory.Exists(dir)) return Array.Empty<AttachmentScanResult>();
        var results = new List<AttachmentScanResult>();
        var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        foreach (var path in Directory.EnumerateFiles(dir, "*", option).OrderBy(p => p))
        {
            ct.ThrowIfCancellationRequested();
            results.Add(await ScanFileAsync(path, ct));
        }
        return results;
    }

    private AttachmentScanResult Classify(ExtractedContent content)
    {
        if (content.HasError || string.IsNullOrEmpty(content.Text))
            return new AttachmentScanResult(content, new ClassificationResult { OriginalText = content.Text });
        var classification = _classifier.Classify(content.Text);
        return new AttachmentScanResult(content, classification);
    }
}

public sealed record AttachmentScanResult(ExtractedContent Content, ClassificationResult Classification);
