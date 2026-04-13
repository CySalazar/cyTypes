using System.Security.Cryptography;
using System.Text;
using CyTypes.AI.Classification;

namespace CyTypes.AI.Tokenization;

public sealed class TokenizationResult
{
    public string TokenizedText { get; init; } = "";
    public int TokenCount { get; init; }
    public IReadOnlyDictionary<string, string> TokenMap { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Bidirectional PII↔token mapping per session. Same value gets the same token within a session.
/// Tokens have format "{type}-{8hex}". Audit trail records token usage without storing plaintext.
/// </summary>
public sealed class PiiTokenizer : IDisposable
{
    public string SessionId { get; }
    private readonly Dictionary<string, string> _valueToToken = new();
    private readonly Dictionary<string, string> _tokenToValue = new();
    private readonly List<string> _audit = new();
    private readonly object _lock = new();

    public PiiTokenizer(string sessionId) { SessionId = sessionId; }

    public TokenizationResult Tokenize(string text, IEnumerable<Finding> findings)
    {
        var sorted = findings.OrderByDescending(f => f.Start).ToList();
        var sb = new StringBuilder(text);
        int count = 0;
        lock (_lock)
        {
            foreach (var f in sorted)
            {
                if (f.Start < 0 || f.Start + f.Length > sb.Length) continue;
                var token = GetOrCreateToken(f);
                sb.Remove(f.Start, f.Length);
                sb.Insert(f.Start, token);
                count++;
                _audit.Add($"{DateTime.UtcNow:O}|tokenize|{f.DataClass}|{Sha256(f.Value)}");
            }
            return new TokenizationResult
            {
                TokenizedText = sb.ToString(),
                TokenCount = count,
                TokenMap = new Dictionary<string, string>(_tokenToValue)
            };
        }
    }

    public string Detokenize(string tokenizedText)
    {
        lock (_lock)
        {
            var sb = new StringBuilder(tokenizedText);
            foreach (var (token, value) in _tokenToValue)
                sb.Replace(token, value);
            _audit.Add($"{DateTime.UtcNow:O}|detokenize|{_tokenToValue.Count}");
            return sb.ToString();
        }
    }

    public IReadOnlyList<string> GetAuditTrail()
    {
        lock (_lock) { return _audit.ToList(); }
    }

    private string GetOrCreateToken(Finding f)
    {
        if (_valueToToken.TryGetValue(f.Value, out var existing)) return existing;
        var typeStr = TypeForToken(f);
        string token;
        if (f.DataClass == Classification.DataClass.Salary)
            token = $"salary-range-{SalaryBucket(f.Value)}";
        else
            token = $"{typeStr}-{Sha256(f.Value).Substring(0, 8)}";
        _valueToToken[f.Value] = token;
        _tokenToValue[token] = f.Value;
        return token;
    }

    private static string TypeForToken(Finding f)
    {
        // Custom company-defined classes use the slugified CustomLabel as
        // token prefix, falling back to "custom" if no label is provided.
        if (f.DataClass == Classification.DataClass.Custom)
            return string.IsNullOrWhiteSpace(f.CustomLabel) ? "custom" : Slug(f.CustomLabel!);
        return f.DataClass switch
        {
            Classification.DataClass.Email => "email",
            Classification.DataClass.PersonName => "person",
            Classification.DataClass.Phone => "phone",
            Classification.DataClass.Iban => "iban",
            Classification.DataClass.CreditCard => "card",
            Classification.DataClass.IpAddress => "ip",
            Classification.DataClass.ApiKey => "apikey",
            Classification.DataClass.Password => "password",
            Classification.DataClass.MedicalTerm => "medical",
            Classification.DataClass.NationalId => "natid",
            Classification.DataClass.FiscalCode => "fiscal",
            Classification.DataClass.Salary => "salary",
            Classification.DataClass.Url => "url",
            Classification.DataClass.Address => "addr",
            _ => f.DataClass.ToString().ToLowerInvariant()
        };
    }

    private static string Slug(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s.ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(ch)) sb.Append(ch);
            else if (sb.Length > 0 && sb[sb.Length - 1] != '-') sb.Append('-');
        }
        return sb.ToString().Trim('-');
    }

    private static string SalaryBucket(string value)
    {
        var digits = new string(value.Where(char.IsDigit).ToArray());
        if (!int.TryParse(digits, out var n)) return "unknown";
        var k = n >= 1000 ? n / 1000 : n;
        var lo = (k / 10) * 10;
        return $"{lo}k-{lo + 10}k";
    }

    private static string Sha256(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _valueToToken.Clear();
            _tokenToValue.Clear();
        }
    }
}
