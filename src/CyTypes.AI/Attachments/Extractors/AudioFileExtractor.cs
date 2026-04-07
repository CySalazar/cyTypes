using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using TagLib;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Audio extractor — runs in two phases:
///   1. <b>Metadata</b> via TagLibSharp (title/artist/album/comment/lyrics/date),
///      always.
///   2. <b>Speech-to-text</b> via Whisper.net (whisper.cpp ggml CPU-only) by
///      default. Three backends, selected via env <c>CYSECURITY_AITEST_AUDIO_STT</c>:
///      • <c>whispernet</c> (default) — local ggml model
///      • <c>ollama</c> — local Ollama HTTP server (must be running on
///        <c>localhost:11434</c> with a Whisper model installed)
///      • <c>metadata-only</c> — skip STT entirely
///
/// **Strict no-cloud policy**: there is no path that calls a remote
/// transcription API. Whisper API (OpenAI), AssemblyAI, Deepgram, AWS
/// Transcribe, Google Speech-to-Text and Azure Speech are explicitly
/// not supported.
/// </summary>
public sealed class AudioFileExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[]
    {
        ".wav", ".mp3", ".aac", ".m4a", ".flac", ".ogg", ".oga", ".opus"
    };

    public override string Format => "audio";

    public static bool SttEnabled { get; set; } = true;

    private static bool? _whisperAvailable;
    private static readonly object _lock = new();

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== Audio: {fileName} ===");

        // ---- Phase 1: metadata via TagLibSharp ----
        try
        {
            stream.Position = 0;
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms, ct);
            ms.Position = 0;
            using var taglibFile = TagLib.File.Create(new StreamFileAbstraction(fileName, ms, ms));
            var tag = taglibFile.Tag;
            void AppendIf(string key, string? v) { if (!string.IsNullOrWhiteSpace(v)) sb.Append(key).Append(": ").AppendLine(v); }
            AppendIf("Title", tag.Title);
            AppendIf("Artists", string.Join(", ", tag.Performers ?? Array.Empty<string>()));
            AppendIf("Album", tag.Album);
            AppendIf("Composer", string.Join(", ", tag.Composers ?? Array.Empty<string>()));
            AppendIf("Comment", tag.Comment);
            AppendIf("Lyrics", tag.Lyrics);
            AppendIf("Genre", string.Join(", ", tag.Genres ?? Array.Empty<string>()));
            if (tag.Year > 0) AppendIf("Year", tag.Year.ToString());
        }
        catch (Exception ex)
        {
            sb.AppendLine($"(metadata extraction failed: {ex.Message})");
        }

        // ---- Phase 2: STT ----
        if (SttEnabled)
        {
            var backend = Environment.GetEnvironmentVariable("CYSECURITY_AITEST_AUDIO_STT")?.ToLowerInvariant() ?? "whispernet";
            try
            {
                stream.Position = 0;
                string? transcript = backend switch
                {
                    "ollama" => await TranscribeViaOllamaAsync(stream, fileName, ct),
                    "metadata-only" => null,
                    _ => await TranscribeViaWhisperNetAsync(stream, ct),
                };
                if (!string.IsNullOrWhiteSpace(transcript))
                {
                    sb.AppendLine();
                    sb.AppendLine("=== Transcript ===");
                    sb.AppendLine(transcript.Trim());
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"(STT skipped: {ex.Message})");
            }
        }

        return sb.ToString();
    }

    private static async Task<string?> TranscribeViaWhisperNetAsync(Stream audioStream, CancellationToken ct)
    {
        if (!IsWhisperAvailable()) return null;
        var modelPath = WhisperModelDownloader.EnsureModel();
        var factory = global::Whisper.net.WhisperFactory.FromPath(modelPath);
        var processor = factory.CreateBuilder().WithLanguage("auto").Build();
        var sb = new StringBuilder();
        // Whisper.net needs a 16 kHz mono PCM WAV. WAV files can be passed as-is;
        // for other formats, the user is expected to use the Ollama backend or
        // metadata-only because we don't ship FFMpeg in the library itself.
        await foreach (var segment in processor.ProcessAsync(audioStream, ct))
        {
            sb.Append(segment.Text);
        }
        processor.Dispose();
        factory.Dispose();
        return sb.ToString();
    }

    private static bool IsWhisperAvailable()
    {
        if (_whisperAvailable is bool b) return b;
        lock (_lock)
        {
            if (_whisperAvailable is bool bb) return bb;
            try
            {
                // Probe by referencing a Whisper.net type
                _ = typeof(global::Whisper.net.WhisperFactory);
                _whisperAvailable = true;
            }
            catch
            {
                _whisperAvailable = false;
            }
            return _whisperAvailable.Value;
        }
    }

    private static async Task<string?> TranscribeViaOllamaAsync(Stream audioStream, string fileName, CancellationToken ct)
    {
        // Ollama exposes /api/transcribe with multipart/form-data audio upload.
        // Localhost only — no cloud allowed.
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        using var content = new MultipartFormDataContent();
        using var ms = new MemoryStream();
        audioStream.Position = 0;
        await audioStream.CopyToAsync(ms, ct);
        ms.Position = 0;
        var fileContent = new StreamContent(ms);
        content.Add(fileContent, "file", fileName);
        var resp = await http.PostAsync("http://localhost:11434/api/transcribe", content, ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Ollama transcribe HTTP {(int)resp.StatusCode}");
        var body = await resp.Content.ReadAsStringAsync(ct);
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("text", out var t) ? t.GetString() : body;
        }
        catch { return body; }
    }
}

/// <summary>
/// Adapter that bridges TagLibSharp's <c>IFileAbstraction</c> over an in-memory stream.
/// TagLibSharp insists on its own file abstraction; this is the minimal wrapper.
/// </summary>
internal sealed class StreamFileAbstraction : TagLib.File.IFileAbstraction
{
    public StreamFileAbstraction(string name, Stream readStream, Stream writeStream)
    {
        Name = name;
        ReadStream = readStream;
        WriteStream = writeStream;
    }

    public string Name { get; }
    public Stream ReadStream { get; }
    public Stream WriteStream { get; }

    public void CloseStream(Stream stream) { /* leave open — caller manages lifetime */ }
}
