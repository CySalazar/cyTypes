namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Downloads Tesseract language data files (<c>*.traineddata</c>) from the
/// official tesseract-ocr/tessdata GitHub mirror to a local cache directory
/// the first time OCR is invoked. CPU-only, no cloud — the files come from
/// HuggingFace's mirror or the official Google Tesseract release; the user
/// can override the URL via env <c>CYSECURITY_TESSDATA_BASE_URL</c>.
/// </summary>
public static class TessdataDownloader
{
    private const string DefaultBase = "https://github.com/tesseract-ocr/tessdata/raw/main";
    public static readonly string[] DefaultLanguages = { "eng", "ita" };

    public static string GetCacheDir()
    {
        var env = Environment.GetEnvironmentVariable("CYSECURITY_TESSDATA_DIR");
        if (!string.IsNullOrEmpty(env)) return env;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".cache", "cytypes-ai", "tessdata");
    }

    /// <summary>Ensures all requested language files are present, downloading on demand.</summary>
    public static string EnsureLanguages(IEnumerable<string>? languages = null, Action<string>? log = null)
    {
        var dir = GetCacheDir();
        Directory.CreateDirectory(dir);
        var baseUrl = Environment.GetEnvironmentVariable("CYSECURITY_TESSDATA_BASE_URL") ?? DefaultBase;
        foreach (var lang in (languages ?? DefaultLanguages))
        {
            var dest = Path.Combine(dir, $"{lang}.traineddata");
            if (File.Exists(dest) && new FileInfo(dest).Length > 1_000_000) continue;
            log?.Invoke($"[tesseract] downloading {lang}.traineddata → {dest}");
            DownloadFile($"{baseUrl}/{lang}.traineddata", dest);
        }
        return dir;
    }

    private static void DownloadFile(string url, string dest)
    {
        // SSRF defense: only allow URLs that point at known public model
        // hosting hosts and don't resolve to private IPs. The base URL is
        // env-overridable so this check is essential.
        SafeUrlValidator.EnsureSafe(url);
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
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
