using System.Security.Cryptography;
using System.Text;
using FFMpegCore;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Video extractor — three-phase pipeline:
///   1. <b>Container metadata</b> via TagLibSharp (title, artist, comment, GPS).
///   2. <b>Audio track → STT</b> via FFMpegCore (extract to PCM 16 kHz mono WAV)
///      → <see cref="AudioFileExtractor"/> (Whisper.net by default).
///   3. <b>Frame OCR</b> via FFMpegCore (1 keyframe every N seconds, env
///      <c>CYSECURITY_AITEST_VIDEO_FRAME_INTERVAL</c>) → perceptual MD5 dedup
///      → <see cref="StandardImageExtractor"/> (Tesseract).
///
/// Requires <c>ffmpeg</c> in <c>PATH</c>. If missing, the extractor returns
/// only the metadata phase with a warning. Strict no-cloud — STT and OCR run
/// locally end-to-end.
/// </summary>
public sealed class VideoFileExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[]
    {
        ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm"
    };
    public override string Format => "video";

    public static int FrameIntervalSeconds { get; set; } =
        int.TryParse(Environment.GetEnvironmentVariable("CYSECURITY_AITEST_VIDEO_FRAME_INTERVAL"), out var v) && v > 0 ? v : 10;

    public static int MaxFrames { get; set; } = 6;

    private static bool? _ffmpegAvailable;
    private static readonly object _lock = new();

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== Video: {fileName} ===");

        // Materialise to a temp file because FFMpeg + TagLib both want a path.
        string tempPath = Path.Combine(Path.GetTempPath(), $"vid-{Guid.NewGuid():N}{Path.GetExtension(fileName)}");
        try
        {
            using (var fs = File.Create(tempPath))
            {
                stream.Position = 0;
                await stream.CopyToAsync(fs, ct);
            }

            // ---- Phase 1: container metadata ----
            try
            {
                var taglib = TagLib.File.Create(tempPath);
                var t = taglib.Tag;
                void Add(string k, string? v) { if (!string.IsNullOrWhiteSpace(v)) sb.Append(k).Append(": ").AppendLine(v); }
                Add("Title", t.Title);
                Add("Performers", string.Join(", ", t.Performers ?? Array.Empty<string>()));
                Add("Album", t.Album);
                Add("Comment", t.Comment);
                Add("Description", t.Description);
                Add("Copyright", t.Copyright);
                taglib.Dispose();
            }
            catch (Exception ex)
            {
                sb.AppendLine($"(metadata extraction failed: {ex.Message})");
            }

            if (!IsFFMpegAvailable())
            {
                sb.AppendLine("(ffmpeg not found in PATH — audio + frame OCR skipped)");
                return sb.ToString();
            }

            // ---- Phase 2: audio → STT ----
            string audioTemp = tempPath + ".wav";
            try
            {
                await FFMpegArguments
                    .FromFileInput(tempPath)
                    .OutputToFile(audioTemp, overwrite: true, opt => opt
                        .WithCustomArgument("-vn -acodec pcm_s16le -ar 16000 -ac 1")
                        .ForceFormat("wav"))
                    .ProcessAsynchronously();

                if (System.IO.File.Exists(audioTemp) && new FileInfo(audioTemp).Length > 1000)
                {
                    using var audioStream = System.IO.File.OpenRead(audioTemp);
                    var audioResult = await AttachmentExtractor.ExtractAsync(audioStream, Path.GetFileName(audioTemp), ct);
                    if (!audioResult.HasError && !string.IsNullOrWhiteSpace(audioResult.Text))
                    {
                        sb.AppendLine();
                        sb.AppendLine("=== Audio track ===");
                        sb.AppendLine(audioResult.Text);
                    }
                }
            }
            catch (Exception ex) { sb.AppendLine($"(audio extraction failed: {ex.Message})"); }
            finally { try { if (System.IO.File.Exists(audioTemp)) System.IO.File.Delete(audioTemp); } catch { } }

            // ---- Phase 3: frame OCR ----
            try
            {
                var frames = await ExtractFramesAsync(tempPath, ct);
                var seenHashes = new HashSet<string>();
                int ocrFrames = 0;
                foreach (var frame in frames)
                {
                    var hash = HashSnippet(frame);
                    if (!seenHashes.Add(hash)) continue;
                    ocrFrames++;
                    using var frameStream = new MemoryStream(frame);
                    var ocr = await AttachmentExtractor.ExtractAsync(frameStream, "frame.png", ct);
                    if (!ocr.HasError && !string.IsNullOrWhiteSpace(ocr.Text))
                    {
                        sb.AppendLine();
                        sb.Append("=== Frame ").Append(ocrFrames).AppendLine(" ===");
                        sb.AppendLine(ocr.Text);
                    }
                }
            }
            catch (Exception ex) { sb.AppendLine($"(frame extraction failed: {ex.Message})"); }
        }
        finally
        {
            try { if (System.IO.File.Exists(tempPath)) System.IO.File.Delete(tempPath); } catch { }
        }

        return sb.ToString();
    }

    private static async Task<List<byte[]>> ExtractFramesAsync(string videoPath, CancellationToken ct)
    {
        var frames = new List<byte[]>();
        var probe = await FFProbe.AnalyseAsync(videoPath);
        var duration = probe.Duration.TotalSeconds;
        if (duration <= 0) return frames;
        int frameCount = Math.Min(MaxFrames, (int)(duration / FrameIntervalSeconds) + 1);
        for (int i = 0; i < frameCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            var atSeconds = i * FrameIntervalSeconds;
            var framePath = Path.Combine(Path.GetTempPath(), $"frm-{Guid.NewGuid():N}.png");
            try
            {
                await FFMpegArguments
                    .FromFileInput(videoPath, verifyExists: true, opt => opt.Seek(TimeSpan.FromSeconds(atSeconds)))
                    .OutputToFile(framePath, overwrite: true, opt => opt
                        .WithFrameOutputCount(1)
                        .ForceFormat("image2"))
                    .ProcessAsynchronously();
                if (System.IO.File.Exists(framePath))
                    frames.Add(await System.IO.File.ReadAllBytesAsync(framePath, ct));
            }
            catch { /* skip frame */ }
            finally { try { if (System.IO.File.Exists(framePath)) System.IO.File.Delete(framePath); } catch { } }
        }
        return frames;
    }

    private static string HashSnippet(byte[] data)
    {
        // Cheap perceptual-ish hash: MD5 of every 64th byte. For OCR dedup we
        // don't need a real perceptual hash — frames that are visually identical
        // produce identical PNG bytes from FFMpeg.
        var sample = new byte[Math.Min(1024, data.Length / 64 + 1)];
        for (int i = 0, j = 0; i < data.Length && j < sample.Length; i += 64, j++) sample[j] = data[i];
        return Convert.ToHexString(MD5.HashData(sample));
    }

    private static bool IsFFMpegAvailable()
    {
        if (_ffmpegAvailable is bool b) return b;
        lock (_lock)
        {
            if (_ffmpegAvailable is bool bb) return bb;
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo("ffmpeg", "-version")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = System.Diagnostics.Process.Start(psi);
                if (p is null) { _ffmpegAvailable = false; return false; }
                p.WaitForExit(2000);
                _ffmpegAvailable = p.ExitCode == 0;
            }
            catch
            {
                _ffmpegAvailable = false;
            }
            return _ffmpegAvailable.Value;
        }
    }
}
