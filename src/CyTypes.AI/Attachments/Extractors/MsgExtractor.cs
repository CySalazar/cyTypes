using MsgReader.Outlook;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// .msg (Microsoft Outlook) extractor — uses MsgReader to walk the OLE
/// compound document and pull headers + body + attachment text.
/// </summary>
public sealed class MsgExtractor : EmailExtractorBase
{
    public override IReadOnlyList<string> SupportedExtensions { get; } = new[] { ".msg" };
    public override string Format => "msg";

    protected override Task<string> ExtractTextAsync(Stream stream, string fileName, CancellationToken ct)
    {
        using var msg = new Storage.Message(stream);
        var from = msg.Sender?.Email ?? msg.Sender?.DisplayName;
        var to = string.Join(", ", msg.Recipients
            .Where(r => r.Type == RecipientType.To)
            .Select(r => r.Email ?? r.DisplayName));
        var cc = string.Join(", ", msg.Recipients
            .Where(r => r.Type == RecipientType.Cc)
            .Select(r => r.Email ?? r.DisplayName));
        var date = msg.SentOn?.ToString("u");
        var body = msg.BodyText ?? msg.BodyHtml;
        return Task.FromResult(FormatEmail(from, to, cc, msg.Subject, date, body));
    }
}
