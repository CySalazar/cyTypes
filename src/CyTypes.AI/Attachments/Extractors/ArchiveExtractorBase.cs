using System.Text;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for archive extractors. Subclasses enumerate <c>(entryName, entryStream)</c>
/// pairs; the base recursively dispatches each entry through
/// <see cref="AttachmentExtractor"/> so PII inside nested files is detected
/// uniformly. Recursion is bounded by <see cref="MaxDepth"/> and
/// <see cref="MaxEntries"/> to prevent zip-bomb DoS.
/// </summary>
public abstract class ArchiveExtractorBase : ExtractorBase
{
    public int MaxDepth { get; set; } = 3;
    public int MaxEntries { get; set; } = 200;

    private static readonly AsyncLocal<int> _currentDepth = new();

    protected abstract IEnumerable<(string entryName, Stream entryStream)> EnumerateEntries(Stream stream);

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        if (_currentDepth.Value >= MaxDepth)
            return $"[archive recursion depth limit reached: {MaxDepth}]";

        _currentDepth.Value++;
        try
        {
            var sb = new StringBuilder();
            sb.Append("=== Archive: ").Append(fileName).AppendLine(" ===");
            int count = 0;
            foreach (var (entryName, entryStream) in EnumerateEntries(stream))
            {
                if (count++ >= MaxEntries)
                {
                    sb.AppendLine($"[entry limit reached: {MaxEntries}]");
                    break;
                }
                ct.ThrowIfCancellationRequested();
                sb.AppendLine();
                sb.Append("--- Entry: ").Append(entryName).AppendLine(" ---");
                using var ms = new MemoryStream();
                try
                {
                    entryStream.CopyTo(ms);
                    ms.Position = 0;
                }
                finally { entryStream.Dispose(); }

                var nested = await AttachmentExtractor.ExtractAsync(ms, entryName, ct);
                if (nested.HasError)
                    sb.Append("(skip: ").Append(nested.Error).AppendLine(")");
                else if (!string.IsNullOrEmpty(nested.Text))
                    sb.AppendLine(nested.Text);
            }
            return sb.ToString();
        }
        finally
        {
            _currentDepth.Value--;
        }
    }
}
