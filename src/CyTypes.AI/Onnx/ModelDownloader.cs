namespace CyTypes.AI.Onnx;

/// <summary>
/// Downloads the GLiNER multi v2.1 ONNX assets (~349 MB INT8 model + 4 MB SentencePiece
/// vocab) on first use to a local cache directory.
/// Override the cache location with env <c>CYSECURITY_PII_MODEL_DIR</c>.
/// </summary>
public static class ModelDownloader
{
    private const string Repo = "onnx-community/gliner_multi-v2.1";
    // Use the FP16 model: INT8 dynamic quantization severely degrades mDeBERTa-v3
    // (the disentangled relative positional attention is sensitive to INT8). FP16
    // is a 553 MB / 350 ms-per-call sweet spot that produces correct logits.
    private static readonly (string url, string filename, long minSize)[] _files =
    {
        ($"https://huggingface.co/{Repo}/resolve/main/onnx/model_fp16.onnx",      "model.onnx",        500_000_000L),
        ($"https://huggingface.co/{Repo}/resolve/main/spm.model",                  "spm.model",         3_000_000L),
        ($"https://huggingface.co/{Repo}/resolve/main/added_tokens.json",          "added_tokens.json",            50L),
        ($"https://huggingface.co/{Repo}/resolve/main/gliner_config.json",         "gliner_config.json",          100L),
    };

    public static string GetCacheDir()
    {
        var env = Environment.GetEnvironmentVariable("CYSECURITY_PII_MODEL_DIR");
        if (!string.IsNullOrEmpty(env)) return env;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".cache", "cytypes-ai", "gliner-multi-v2.1");
    }

    /// <summary>Returns (modelPath, spmPath); downloads any missing/truncated file first.</summary>
    public static (string modelPath, string spmPath) GetOrDownload(Action<string>? log = null)
    {
        var dir = GetCacheDir();
        Directory.CreateDirectory(dir);
        foreach (var (url, fname, minSize) in _files)
        {
            var dest = Path.Combine(dir, fname);
            if (File.Exists(dest) && new FileInfo(dest).Length >= minSize) continue;
            log?.Invoke($"[gliner] downloading {fname} ({minSize / 1_000_000} MB+) → {dest}");
            DownloadFile(url, dest);
        }
        return (Path.Combine(dir, "model.onnx"), Path.Combine(dir, "spm.model"));
    }

    private static void DownloadFile(string url, string dest)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
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
