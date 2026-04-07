using System.Text;

namespace CyTypes.AI.Attachments.Extractors;

/// <summary>
/// Common base for email extractors — formats the standard header block
/// (From / To / Cc / Subject / Date) and the body in a uniform way so the
/// classifier sees a predictable layout regardless of source format.
/// </summary>
public abstract class EmailExtractorBase : ExtractorBase
{
    protected static string FormatEmail(
        string? from,
        string? to,
        string? cc,
        string? subject,
        string? date,
        string? body,
        IEnumerable<(string name, string text)>? nestedAttachments = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Email headers ===");
        if (!string.IsNullOrWhiteSpace(from))    sb.Append("From: ").AppendLine(from);
        if (!string.IsNullOrWhiteSpace(to))      sb.Append("To: ").AppendLine(to);
        if (!string.IsNullOrWhiteSpace(cc))      sb.Append("Cc: ").AppendLine(cc);
        if (!string.IsNullOrWhiteSpace(subject)) sb.Append("Subject: ").AppendLine(subject);
        if (!string.IsNullOrWhiteSpace(date))    sb.Append("Date: ").AppendLine(date);
        sb.AppendLine();
        sb.AppendLine("=== Body ===");
        if (!string.IsNullOrWhiteSpace(body)) sb.AppendLine(body);
        if (nestedAttachments is not null)
        {
            foreach (var (name, text) in nestedAttachments)
            {
                if (string.IsNullOrWhiteSpace(text)) continue;
                sb.AppendLine();
                sb.Append("=== Nested attachment: ").Append(name).AppendLine(" ===");
                sb.AppendLine(text);
            }
        }
        return sb.ToString();
    }
}
