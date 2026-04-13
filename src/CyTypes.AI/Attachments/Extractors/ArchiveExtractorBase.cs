using System.Text;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for archive extractors. Subclasses enumerate <c>(entryName, entryStream)</c>
/// pairs; the base recursively dispatches each entry through
/// <see cref="AttachmentExtractor"/> so PII inside nested files is detected
/// uniformly. Recursion + entry count + entry size are all bounded to prevent
/// zip-bomb DoS.
/// </summary>
public abstract class ArchiveExtractorBase : ExtractorBase
{
    /// <summary>Maximum nesting depth (zip-in-zip-in-zip).</summary>
    public int MaxDepth { get; set; } = 3;

    /// <summary>Maximum number of entries to read from a single archive.</summary>
    public int MaxEntries { get; set; } = 200;

    /// <summary>Maximum decompressed size in bytes per entry. Defaults to 100 MB.</summary>
    public long MaxBytesPerEntry { get; set; } = 100L * 1024 * 1024;

    /// <summary>Maximum aggregate decompressed bytes across all entries in an archive (including nested). Defaults to 500 MB.</summary>
    public long MaxTotalBytes { get; set; } = 500L * 1024 * 1024;

    private static readonly AsyncLocal<int> _currentDepth = new();
    private static readonly AsyncLocal<long> _totalBytesDecompressed = new();

    protected abstract IEnumerable<(string entryName, Stream entryStream)> EnumerateEntries(Stream stream);

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        if (_currentDepth.Value >= MaxDepth)
            return $"[archive recursion depth limit reached: {MaxDepth}]";

        bool isRoot = _currentDepth.Value == 0;
        if (isRoot) _totalBytesDecompressed.Value = 0;
        _currentDepth.Value++;
        try
        {
            var sb = new StringBuilder();
            sb.Append("=== Archive: ").Append(fileName).AppendLine(" ===");
            int count = 0;
            foreach (var (rawEntryName, entryStream) in EnumerateEntries(stream))
            {
                if (count++ >= MaxEntries)
                {
                    sb.AppendLine($"[entry limit reached: {MaxEntries}]");
                    break;
                }
                ct.ThrowIfCancellationRequested();

                // Sanitize the entry name: archive entries can contain ../ path
                // traversal sequences (zip-slip) and Windows drive letters. We
                // never write to disk with this name, but it's reflected in
                // logs and re-dispatched, so reduce it to a safe leaf basename.
                var entryName = SanitizeEntryName(rawEntryName);

                sb.AppendLine();
                sb.Append("--- Entry: ").Append(entryName).AppendLine(" ---");

                // Per-entry size cap: copy at most MaxBytesPerEntry bytes from
                // the entry stream. This protects against a single 10 GB entry
                // exploding the buffer in memory ("zip bomb" with N=1).
                // Check aggregate limit before starting a new entry
                if (_totalBytesDecompressed.Value >= MaxTotalBytes)
                {
                    entryStream.Dispose();
                    sb.AppendLine($"[aggregate decompression limit reached: {MaxTotalBytes} bytes]");
                    break;
                }

                using var ms = new MemoryStream();
                bool truncated = false;
                try
                {
                    var buffer = new byte[81920];
                    int read;
                    while ((read = entryStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (ms.Length + read > MaxBytesPerEntry ||
                            _totalBytesDecompressed.Value + ms.Length + read > MaxTotalBytes)
                        {
                            long perEntryRoom = MaxBytesPerEntry - ms.Length;
                            long totalRoom = MaxTotalBytes - _totalBytesDecompressed.Value - ms.Length;
                            int allowed = (int)Math.Max(0, Math.Min(Math.Min(perEntryRoom, totalRoom), read));
                            if (allowed > 0) ms.Write(buffer, 0, allowed);
                            truncated = true;
                            break;
                        }
                        ms.Write(buffer, 0, read);
                    }
                    _totalBytesDecompressed.Value += ms.Length;
                    ms.Position = 0;
                }
                finally { entryStream.Dispose(); }

                if (truncated)
                    sb.Append("[entry truncated at ").Append(MaxBytesPerEntry).AppendLine(" bytes]");

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

    /// <summary>
    /// Reduce a raw archive-entry name to a safe leaf filename. Strips any
    /// directory components, drive letters, parent-directory references,
    /// and replaces empty / dot-only names with a placeholder. This is
    /// defence-in-depth — we don't write to disk with this name, but it
    /// gets reflected in logs and re-dispatched to other extractors that
    /// might be confused by tricky inputs.
    /// </summary>
    private static string SanitizeEntryName(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "(unnamed)";
        // Normalise both separators
        var normalised = raw.Replace('\\', '/');
        // Take just the leaf
        var leaf = normalised.Split('/').LastOrDefault(s => !string.IsNullOrEmpty(s)) ?? "(unnamed)";
        // Strip dots and any remaining directory traversal
        if (leaf is "." or "..") return "(unnamed)";
        // Strip Windows drive prefix if leaked through (e.g. "C:foo")
        if (leaf.Length >= 2 && leaf[1] == ':') leaf = leaf.Substring(2);
        // Replace any remaining filesystem-special chars with underscore
        foreach (var c in Path.GetInvalidFileNameChars())
            leaf = leaf.Replace(c, '_');
        return string.IsNullOrWhiteSpace(leaf) ? "(unnamed)" : leaf;
    }
}
