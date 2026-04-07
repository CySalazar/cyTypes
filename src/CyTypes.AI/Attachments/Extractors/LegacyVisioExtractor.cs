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

        // Use a per-call private temp directory and a fixed safe inner filename
        // (`input.vsd`) instead of trusting the caller-supplied name. This:
        //   1. Avoids any chance of command injection via filename metacharacters
        //   2. Prevents the symlink-race attack on /tmp because Directory.CreateDirectory
        //      is atomic and the directory is owned by us
        //   3. Makes the cleanup deterministic (Dispose deletes the whole subtree)
        using var tempDir = new SafeTempDir("vsd-");
        var vsdPath = Path.Combine(tempDir.Path, "input.vsd");
        await using (var fs = File.Create(vsdPath))
        {
            stream.Position = 0;
            await stream.CopyToAsync(fs, ct);
        }

        // Use ArgumentList instead of an interpolated Arguments string so that
        // each argument is passed as a separate argv entry — no shell parsing,
        // no quoting bugs, no command injection surface.
        var psi = new ProcessStartInfo("soffice")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--headless");
        psi.ArgumentList.Add("--convert-to");
        psi.ArgumentList.Add("pdf");
        psi.ArgumentList.Add(vsdPath);
        psi.ArgumentList.Add("--outdir");
        psi.ArgumentList.Add(tempDir.Path);

        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start 'soffice' process.");
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0)
            throw new InvalidOperationException(
                $"LibreOffice exited with code {p.ExitCode}: {await p.StandardError.ReadToEndAsync(ct)}");

        var pdfPath = Path.Combine(tempDir.Path, "input.pdf");
        if (!File.Exists(pdfPath))
            throw new InvalidOperationException("LibreOffice did not produce a PDF output");

        await using var pdfStream = File.OpenRead(pdfPath);
        var result = await AttachmentExtractor.ExtractAsync(pdfStream, "input.pdf", ct);
        return result.HasError ? $"(inner PDF extractor error: {result.Error})" : result.Text;
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
