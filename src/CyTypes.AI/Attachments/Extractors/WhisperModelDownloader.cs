namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Downloads the whisper.cpp ggml model from HuggingFace's official mirror to a
/// local cache directory the first time STT is invoked. CPU-only — the file
/// is the standard ggml format consumed by Whisper.net's native runtime.
/// Override the cache via env <c>CYSECURITY_WHISPER_DIR</c>; override the
/// model variant via env <c>CYSECURITY_WHISPER_MODEL</c> (default <c>base</c>).
/// </summary>
public static class WhisperModelDownloader
{
    private const string DefaultModel = "base";
    private const string Repo = "ggerganov/whisper.cpp";

    public static string GetCacheDir()
    {
        var env = Environment.GetEnvironmentVariable("CYSECURITY_WHISPER_DIR");
        if (!string.IsNullOrEmpty(env)) return env;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".cache", "cytypes-ai", "whisper");
    }

    public static string EnsureModel(Action<string>? log = null)
    {
        var dir = GetCacheDir();
        Directory.CreateDirectory(dir);
        var variant = Environment.GetEnvironmentVariable("CYSECURITY_WHISPER_MODEL") ?? DefaultModel;
        var fname = $"ggml-{variant}.bin";
        var dest = Path.Combine(dir, fname);
        if (File.Exists(dest) && new FileInfo(dest).Length > 50_000_000) return dest;
        log?.Invoke($"[whisper] downloading {fname} (~140 MB) → {dest}");
        DownloadFile($"https://huggingface.co/{Repo}/resolve/main/{fname}", dest);
        return dest;
    }

    private static void DownloadFile(string url, string dest)
    {
        // SSRF defense: see SafeUrlValidator. Whisper.cpp ggml models are
        // hosted on huggingface.co so the allow-list covers them.
        SafeUrlValidator.EnsureSafe(url);
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(15) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("CyTypes.AI/1.0");
        using var resp = http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
        using var src = resp.Content.ReadAsStream();
        var tmp = dest + ".part";
        using (var dst = File.Create(tmp)) src.CopyTo(dst);
        if (File.Exists(dest)) File.Delete(dest);
        File.Move(tmp, dest);
    }
}
