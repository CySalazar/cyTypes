using System.Diagnostics;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Legacy Visio (.vsd, binary OLE compound) extractor — there is no managed
/// .NET reader for the old .vsd format, so we delegate to LibreOffice headless:
///
/// <code>soffice --headless --convert-to pdf input.vsd --outdir tmpdir</code>
///
/// The resulting PDF is then routed through <see cref="PdfExtractor"/> via the
/// dispatcher. Requires <c>libreoffice</c> in <c>PATH</c>; if missing, returns
/// a clear error message via <see cref="ExtractedContent.Error"/>.
/// </summary>
public sealed class LegacyVisioExtractor : ExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".vsd" };
    public override string Format => "vsd";

    private static bool? _libreOfficeAvailable;
    private static readonly object _lock = new();

    protected override async Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        if (!IsLibreOfficeAvailable())
            throw new InvalidOperationException("LibreOffice ('soffice') not found in PATH. Install libreoffice-core to enable .vsd extraction.");

        // Materialise to a temp file for LibreOffice.
        string tempDir = Path.Combine(Path.GetTempPath(), $"vsd-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string vsdPath = Path.Combine(tempDir, fileName);
        try
        {
            using (var fs = File.Create(vsdPath))
            {
                stream.Position = 0;
                await stream.CopyToAsync(fs, ct);
            }

            var psi = new ProcessStartInfo("soffice", $"--headless --convert-to pdf \"{vsdPath}\" --outdir \"{tempDir}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            await p.WaitForExitAsync(ct);
            if (p.ExitCode != 0)
                throw new InvalidOperationException($"LibreOffice exited with code {p.ExitCode}: {await p.StandardError.ReadToEndAsync(ct)}");

            var pdfPath = Path.Combine(tempDir, Path.GetFileNameWithoutExtension(fileName) + ".pdf");
            if (!File.Exists(pdfPath))
                throw new InvalidOperationException("LibreOffice did not produce a PDF output");

            using var pdfStream = File.OpenRead(pdfPath);
            var result = await AttachmentExtractor.ExtractAsync(pdfStream, Path.GetFileName(pdfPath), ct);
            return result.HasError ? $"(inner PDF extractor error: {result.Error})" : result.Text;
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static bool IsLibreOfficeAvailable()
    {
        if (_libreOfficeAvailable is bool b) return b;
        lock (_lock)
        {
            if (_libreOfficeAvailable is bool bb) return bb;
            try
            {
                var psi = new ProcessStartInfo("soffice", "--version")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p is null) { _libreOfficeAvailable = false; return false; }
                p.WaitForExit(2000);
                _libreOfficeAvailable = p.ExitCode == 0;
            }
            catch
            {
                _libreOfficeAvailable = false;
            }
            return _libreOfficeAvailable.Value;
        }
    }
}
