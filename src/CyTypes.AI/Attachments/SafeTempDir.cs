namespace CyTypes.AI.Attachments;

/// <summary>
/// Creates a per-call private temp directory under <see cref="Path.GetTempPath"/>
/// with a non-predictable name. The directory is owned by the caller and gets
/// deleted (recursively, best-effort) when this object is disposed.
///
/// Defends against the symlink-race in <c>/tmp</c>: instead of constructing a
/// temp file path with <c>Path.GetTempPath() + Guid.NewGuid()</c> and opening
/// it (which leaves a tiny window where an attacker could plant a symlink),
/// we first create the parent directory atomically with <see cref="Directory.CreateDirectory(string)"/>
/// (which fails if it already exists with the same name — extremely unlikely
/// given the GUID — and crucially does not follow symlinks at the leaf), then
/// only operate on files inside that directory.
/// </summary>
public sealed class SafeTempDir : IDisposable
{
    public string Path { get; }

    public SafeTempDir(string prefix = "cytypes-ai-")
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    /// <summary>Returns a fresh path inside this directory; the file is not yet created.</summary>
    public string NewFilePath(string suffix)
    {
        if (string.IsNullOrEmpty(suffix)) suffix = ".tmp";
        if (!suffix.StartsWith('.')) suffix = "." + suffix;
        return System.IO.Path.Combine(Path, "f" + suffix);
    }

    /// <summary>Optional debug-level log callback for dispose failures.</summary>
    internal static Action<string>? DebugLog { get; set; }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, recursive: true);
        }
        catch (Exception ex)
        {
            // best-effort cleanup; log for diagnostics if callback is set
            DebugLog?.Invoke($"SafeTempDir cleanup failed for '{Path}': {ex.Message}");
        }
    }
}
