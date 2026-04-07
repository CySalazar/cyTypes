using System.Text;
using XstReader;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .pst / .ost (Outlook personal store) extractor — uses XstReader.Api,
/// a pure-managed .NET Standard reader. Walks every folder recursively
/// and emits one block per message in the standard email layout (headers
/// + body) so the classifier sees PII identically to .eml/.msg files.
/// </summary>
public sealed class XstExtractor : EmailExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".pst", ".ost" };
    public override string Format => "pst";

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        // XstReader requires a path, not a stream. If we got a non-FileStream,
        // dump to an atomic per-call temp directory.
        if (stream is FileStream fs)
            return Task.FromResult(WalkPst(fs.Name, ct));

        using var safeDir = new SafeTempDir("xst-");
        var tempPath = Path.Combine(safeDir.Path, "store" + Path.GetExtension(fileName));
        using (var temp = File.Create(tempPath))
        {
            stream.Position = 0;
            stream.CopyTo(temp);
        }
        return Task.FromResult(WalkPst(tempPath, ct));
    }

    private static string WalkPst(string path, CancellationToken ct)
    {
        using var xst = new XstFile(path);
        var sb = new StringBuilder();
        int messageCount = 0;
        WalkFolder(xst.RootFolder, sb, ref messageCount, ct);
        sb.Insert(0, $"=== PST store: {messageCount} messages ===\n\n");
        return sb.ToString();
    }

    private static void WalkFolder(XstFolder folder, StringBuilder sb, ref int counter, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        foreach (var msg in folder.Messages)
        {
            counter++;
            string body;
            try { body = msg.Body?.Text ?? string.Empty; }
            catch { body = string.Empty; }
            sb.Append(FormatEmail(
                from: msg.From,
                to: msg.To,
                cc: msg.Cc,
                subject: msg.Subject,
                date: msg.Date?.ToString("u"),
                body: body));
            sb.AppendLine();
        }
        foreach (var sub in folder.Folders)
            WalkFolder(sub, sb, ref counter, ct);
    }
}
