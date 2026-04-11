using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CyTypes.AI.Classification;
using CyTypes.AI.Plugin;
using CyTypes.AI.Provider;
using CyTypes.AI.Tokenization;

namespace CyTypes.AI;

// =================== AI Response =====================

public sealed class AIResponse
{
    public string Response { get; init; } = "";
    public int PiiTokenized { get; init; }
    public decimal Cost { get; init; }
    public string CorrelationId { get; init; } = "";
    public string Provider { get; init; } = "";
    public string Model { get; init; } = "";
    public bool Blocked { get; init; }
    public string? BlockReason { get; init; }
}

// =================== Audit Log =====================

public sealed record AuditEntry(
    DateTime Timestamp,
    string CorrelationId,
    string Event,
    string Detail,
    string Hmac,
    string PrevHmac);

public sealed class CyAuditLog
{
    private readonly List<AuditEntry> _entries = new();
    private readonly byte[] _key;
    private string _prev = new('0', 64);

    public CyAuditLog()
    {
        _key = new byte[32];
        RandomNumberGenerator.Fill(_key);
    }

    public void Append(string correlationId, string evt, string detail)
    {
        var ts = DateTime.UtcNow;
        var payload = $"{ts:O}|{correlationId}|{evt}|{detail}|{_prev}";
        var hmac = Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
        _entries.Add(new AuditEntry(ts, correlationId, evt, detail, hmac, _prev));
        _prev = hmac;
    }

    public IReadOnlyList<AuditEntry> GetAll() => _entries;

    public IReadOnlyList<AuditEntry> GetTrace(string correlationId)
        => _entries.Where(e => e.CorrelationId == correlationId).ToList();

    public bool VerifyIntegrity()
    {
        var prev = new string('0', 64);
        foreach (var e in _entries)
        {
            var payload = $"{e.Timestamp:O}|{e.CorrelationId}|{e.Event}|{e.Detail}|{prev}";
            var expected = Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
            if (expected != e.Hmac) return false;
            prev = e.Hmac;
        }
        return true;
    }
}

// =================== Prompt Guard =====================

public sealed class PromptGuardResult
{
    public bool InjectionDetected { get; init; }
    public List<string> SuspiciousPatterns { get; init; } = new();
    public string SanitizedPrompt { get; init; } = "";
}

public sealed class PromptGuard
{
    private static readonly string[] _injectionMarkers =
    {
        "ignore previous instructions","ignore all previous","disregard previous",
        "ignora le istruzioni precedenti","forget what i told you","you are now",
        "act as if","jailbreak","developer mode","DAN mode","system: ","</system>"
    };
    private readonly DataClassifier? _classifier;
    public PromptGuard(DataClassifier? classifier = null) { _classifier = classifier; }

    public PromptGuardResult Sanitize(string prompt)
    {
        var lower = prompt.ToLowerInvariant();
        var found = _injectionMarkers.Where(m => lower.Contains(m)).ToList();
        // Strip zero-width chars
        var cleaned = Regex.Replace(prompt, @"[\u200B-\u200F\u202A-\u202E\uFEFF]", "");
        return new PromptGuardResult
        {
            InjectionDetected = found.Count > 0,
            SuspiciousPatterns = found,
            SanitizedPrompt = cleaned
        };
    }
}

// =================== Response Validator =====================

public sealed class ValidationIssue
{
    public string Category { get; init; } = "";
    public string Snippet { get; init; } = "";
    public string Severity { get; init; } = "Medium";
}

public sealed class ValidationResult
{
    public bool IsClean => Issues.Count == 0;
    public List<ValidationIssue> Issues { get; init; } = new();
}

public sealed class ResponseValidator
{
    private static readonly (string cat, Regex rx, string sev)[] _checks =
    {
        ("SQLi",       new Regex(@"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.+?\+\s*\w+", RegexOptions.Compiled), "High"),
        ("XSS",        new Regex(@"innerHTML\s*=|document\.write\(", RegexOptions.Compiled), "High"),
        ("CmdInject",  new Regex(@"(?i)Runtime\.getRuntime\(\)\.exec|Process\.Start\(.*\+", RegexOptions.Compiled), "Critical"),
        ("Secret",     new Regex(@"(?i)(api[_-]?key|secret|password|token)\s*=\s*[""'][^""']{8,}[""']", RegexOptions.Compiled), "High"),
        ("WeakCrypto", new Regex(@"(?i)\b(MD5|SHA1|DES|RC4)\b", RegexOptions.Compiled), "Medium"),
    };

    public ValidationResult Validate(string code)
    {
        var r = new ValidationResult();
        foreach (var (cat, rx, sev) in _checks)
            foreach (Match m in rx.Matches(code))
                r.Issues.Add(new ValidationIssue { Category = cat, Snippet = m.Value, Severity = sev });
        return r;
    }
}

// =================== Token Budget Manager =====================

public sealed class BudgetOptions
{
    public decimal DailyLimit { get; set; } = 100m;
    public decimal MonthlyLimit { get; set; } = 2000m;
    public decimal PerUserDailyLimit { get; set; } = 10m;
    public double AlertThreshold { get; set; } = 0.8;
}

public sealed class BudgetAlertEventArgs : EventArgs
{
    public string Scope { get; init; } = "";
    public decimal Spent { get; init; }
    public decimal Limit { get; init; }
}

public sealed class TokenBudgetManager
{
    private readonly BudgetOptions _o;
    private readonly Dictionary<string, decimal> _userDaily = new();
    private decimal _daily;
    private decimal _monthly;
    private DateTime _dayKey = DateTime.UtcNow.Date;
    private (int Y, int M) _monthKey = (DateTime.UtcNow.Year, DateTime.UtcNow.Month);

    public event EventHandler<BudgetAlertEventArgs>? BudgetAlert;

    public TokenBudgetManager(BudgetOptions o) { _o = o; }

    private void Roll()
    {
        var today = DateTime.UtcNow.Date;
        if (today != _dayKey) { _daily = 0; _userDaily.Clear(); _dayKey = today; }
        var mk = (DateTime.UtcNow.Year, DateTime.UtcNow.Month);
        if (mk != _monthKey) { _monthly = 0; _monthKey = mk; }
    }

    public bool CanSpend(string userId, decimal cost)
    {
        Roll();
        if (_daily + cost > _o.DailyLimit) return false;
        if (_monthly + cost > _o.MonthlyLimit) return false;
        var u = _userDaily.GetValueOrDefault(userId);
        if (u + cost > _o.PerUserDailyLimit) return false;
        return true;
    }

    public void RecordSpend(string userId, decimal cost)
    {
        Roll();
        _daily += cost; _monthly += cost;
        _userDaily[userId] = _userDaily.GetValueOrDefault(userId) + cost;
        Check("daily", _daily, _o.DailyLimit);
        Check("monthly", _monthly, _o.MonthlyLimit);
        Check($"user:{userId}", _userDaily[userId], _o.PerUserDailyLimit);
    }

    private void Check(string scope, decimal spent, decimal limit)
    {
        if (limit <= 0) return;
        if ((double)(spent / limit) >= _o.AlertThreshold)
            BudgetAlert?.Invoke(this, new BudgetAlertEventArgs { Scope = scope, Spent = spent, Limit = limit });
    }

    public decimal GetDailySpent() { Roll(); return _daily; }
    public decimal GetMonthlySpent() { Roll(); return _monthly; }
    public decimal GetUserSpent(string userId) { Roll(); return _userDaily.GetValueOrDefault(userId); }
}

// =================== Model Registry =====================

public enum UseCase { CodeReview, Documentation, DataAnalysis, MedicalAdvice, LegalAdvice, FinancialAdvice, GeneralChat }
public enum DataClassification { PublicInfo, InternalOnly, Confidential, Restricted, MedicalRecord }
public enum RiskLevel { Low, Medium, High }

public sealed class ApprovedModel
{
    public string Id { get; set; } = "";
    public string Provider { get; set; } = "";
    public RiskLevel RiskLevel { get; set; }
    public List<UseCase> ApprovedFor { get; set; } = new();
    public DataClassification MaxDataClassification { get; set; }
    public string ApprovedBy { get; set; } = "";
    public DateTime ApprovedDate { get; set; }
}

public sealed record ApprovalDecision(bool Approved, string Reason);

public sealed class ModelRegistry
{
    private readonly Dictionary<string, ApprovedModel> _models = new();
    public void Register(ApprovedModel m) => _models[m.Id] = m;

    public ApprovalDecision CheckApproval(string modelId, UseCase useCase, DataClassification dataClass)
    {
        if (!_models.TryGetValue(modelId, out var m)) return new ApprovalDecision(false, $"Model {modelId} not registered");
        if (!m.ApprovedFor.Contains(useCase)) return new ApprovalDecision(false, $"Use case {useCase} not approved");
        if (dataClass > m.MaxDataClassification) return new ApprovalDecision(false, $"Data class {dataClass} exceeds max {m.MaxDataClassification}");
        return new ApprovalDecision(true, "Approved");
    }

    public IReadOnlyCollection<ApprovedModel> All => _models.Values;
}

// =================== CyAI gateway =====================

public sealed class CyAIOptions
{
    internal readonly List<ICompliancePlugin> Plugins = new();
    public TokenBudgetManager? Budget { get; set; }
    public ModelRegistry? Registry { get; set; }

    public CyAIOptions WithGdpr() { Plugins.Add(new GdprPlugin()); return this; }
    public CyAIOptions WithNis2() { Plugins.Add(new Nis2Plugin()); return this; }
    public CyAIOptions WithHipaa() { Plugins.Add(new HipaaPlugin()); return this; }
    public CyAIOptions WithCcpa() { Plugins.Add(new CcpaPlugin()); return this; }
    public CyAIOptions WithPciDss() { Plugins.Add(new PciDssPlugin()); return this; }
    public CyAIOptions WithPlugin(ICompliancePlugin p) { Plugins.Add(p); return this; }
}

public sealed class CyAI
{
    private readonly CyAIOptions _o;
    private readonly Dictionary<string, IAIProvider> _providers = new(StringComparer.OrdinalIgnoreCase);
    private readonly DataClassifier _classifier;
    private readonly PromptGuard _guard;
    private readonly ResponseValidator _validator = new();
    private readonly CyAuditLog _audit = new();

    public CyAI(CyAIOptions options)
    {
        _o = options;
        _classifier = new DataClassifier(new LocalLlmClassifier());
        foreach (var p in options.Plugins) _classifier.AddPlugin(p);
        _guard = new PromptGuard(_classifier);
    }

    public void AddProvider(string name, IAIProvider provider)
    {
        _providers[name] = provider;
        _audit.Append("system", "ProviderRegistered", $"name={name} model={provider.Model}");
    }

    public IReadOnlyCollection<string> ProviderNames => _providers.Keys;

    public Task<AIResponse> Ask(string prompt, string provider, string userId, CancellationToken ct = default)
        => AskCore(
            systemPrompt: null,
            messages: new[] { new ChatMessage("user", prompt) },
            provider: provider,
            userId: userId,
            ct: ct);

    /// <summary>
    /// Multi-turn overload. Applies the full CyTypes.AI compliance pipeline
    /// (PromptGuard → DataClassifier → PiiTokenizer → plugin rules → budget →
    /// provider → ResponseValidator → detokenize) to every turn in the
    /// conversation and forwards the tokenized transcript to the provider via
    /// its native chat API. Callers must pass the messages in chronological
    /// order; each <see cref="ChatMessage.Role"/> should be one of "system",
    /// "user" or "assistant".
    /// </summary>
    public Task<AIResponse> Ask(
        IReadOnlyList<ChatMessage> messages,
        string? systemPrompt,
        string provider,
        string userId,
        CancellationToken ct = default)
        => AskCore(systemPrompt, messages, provider, userId, ct);

    private async Task<AIResponse> AskCore(
        string? systemPrompt,
        IReadOnlyList<ChatMessage> messages,
        string provider,
        string userId,
        CancellationToken ct)
    {
        var corr = Guid.NewGuid().ToString("n");
        _audit.Append(corr, "RequestStart", $"user={userId} provider={provider} turns={messages.Count}");

        // Injection check + classify run per-turn; a single injected message is
        // enough to block the whole request. Findings are aggregated for the
        // compliance gate.
        var classifiedTurns = new List<(string role, string sanitized, ClassificationResult cls)>(messages.Count);
        ClassificationResult? systemCls = null;
        string? sanitizedSystem = null;

        if (!string.IsNullOrEmpty(systemPrompt))
        {
            var sGuard = _guard.Sanitize(systemPrompt!);
            if (sGuard.InjectionDetected)
            {
                _audit.Append(corr, "ComplianceBlocked", $"prompt-injection(system): {string.Join(",", sGuard.SuspiciousPatterns)}");
                return new AIResponse { CorrelationId = corr, Blocked = true, BlockReason = "prompt injection", Provider = provider };
            }
            sanitizedSystem = sGuard.SanitizedPrompt;
            systemCls = _classifier.Classify(sanitizedSystem);
        }

        foreach (var m in messages)
        {
            var guard = _guard.Sanitize(m.Content ?? string.Empty);
            if (guard.InjectionDetected)
            {
                _audit.Append(corr, "ComplianceBlocked", $"prompt-injection({m.Role}): {string.Join(",", guard.SuspiciousPatterns)}");
                return new AIResponse { CorrelationId = corr, Blocked = true, BlockReason = "prompt injection", Provider = provider };
            }
            var cls = _classifier.Classify(guard.SanitizedPrompt);
            classifiedTurns.Add((m.Role, guard.SanitizedPrompt, cls));
        }

        int totalFindings = classifiedTurns.Sum(t => t.cls.Findings.Count) + (systemCls?.Findings.Count ?? 0);
        _audit.Append(corr, "PiiClassified", $"findings={totalFindings}");

        // Aggregate compliance-block decisions across every turn.
        var allFindings = classifiedTurns.SelectMany(t => t.cls.Findings).ToList();
        if (systemCls != null) allFindings.AddRange(systemCls.Findings);
        var blocked = allFindings
            .SelectMany(f => _o.Plugins.SelectMany(p => p.GetRules().Where(r => r.DataClass == f.DataClass && r.Action == DataAction.Block)))
            .ToList();
        if (blocked.Count > 0)
        {
            _audit.Append(corr, "ComplianceBlocked", $"rules={string.Join(",", blocked.Select(b => b.Description))}");
            return new AIResponse { CorrelationId = corr, Blocked = true, BlockReason = blocked[0].Description, Provider = provider };
        }

        using var tokenizer = new PiiTokenizer(corr);
        int totalTokenizedCount = 0;

        string? tokenizedSystem = null;
        if (sanitizedSystem != null && systemCls != null)
        {
            var sTok = tokenizer.Tokenize(sanitizedSystem, systemCls.Findings);
            tokenizedSystem = sTok.TokenizedText;
            totalTokenizedCount += sTok.TokenCount;
        }

        var tokenizedTurns = new List<ChatMessage>(classifiedTurns.Count);
        foreach (var t in classifiedTurns)
        {
            var tok = tokenizer.Tokenize(t.sanitized, t.cls.Findings);
            totalTokenizedCount += tok.TokenCount;
            tokenizedTurns.Add(new ChatMessage(t.role, tok.TokenizedText));
        }
        _audit.Append(corr, "PiiTokenized", $"count={totalTokenizedCount}");
        _audit.Append(corr, "CompliancePassed", $"plugins={_o.Plugins.Count}");

        if (!_providers.TryGetValue(provider, out var prov))
            throw new InvalidOperationException($"Provider '{provider}' not registered");

        if (_o.Budget != null && !_o.Budget.CanSpend(userId, 0.01m))
        {
            _audit.Append(corr, "BudgetBlocked", $"user={userId}");
            return new AIResponse { CorrelationId = corr, Blocked = true, BlockReason = "budget exceeded", Provider = provider };
        }

        _audit.Append(corr, "ProviderCallStart", $"model={prov.Model}");
        ProviderCallResult call;
        try
        {
            call = await prov.CompleteAsync(tokenizedTurns, tokenizedSystem, ct);
        }
        catch (Exception ex)
        {
            _audit.Append(corr, "ProviderCallError", ex.GetType().Name);
            throw;
        }
        _audit.Append(corr, "ProviderCallSuccess", $"in={call.InputTokens} out={call.OutputTokens} cost={call.EstimatedCost}");

        _o.Budget?.RecordSpend(userId, call.EstimatedCost);

        var validation = _validator.Validate(call.Text);
        if (!validation.IsClean)
            _audit.Append(corr, "ResponseSecurityIssues", $"count={validation.Issues.Count}");

        var detok = tokenizer.Detokenize(call.Text);
        _audit.Append(corr, "PiiRestored", $"tokens={totalTokenizedCount}");
        _audit.Append(corr, "RequestComplete", "ok");

        return new AIResponse
        {
            Response = detok,
            PiiTokenized = totalTokenizedCount,
            Cost = call.EstimatedCost,
            CorrelationId = corr,
            Provider = provider,
            Model = prov.Model
        };
    }

    public IReadOnlyList<AuditEntry> GetAuditLog() => _audit.GetAll();
    public IReadOnlyList<AuditEntry> GetRequestTrace(string correlationId) => _audit.GetTrace(correlationId);
    public bool VerifyAuditIntegrity() => _audit.VerifyIntegrity();
}

// =================== Minimal in-memory RAG context =====================

public interface ICyRagContext : IDisposable
{
    string Mode { get; }
    string EmbeddingProvider { get; }
    int IndexedChunks { get; }
    int IngestedDocuments { get; }
    Task IngestTextAsync(string text, string? sourceId = null, CancellationToken ct = default);
    Task IngestFileAsync(string filePath, CancellationToken ct = default);
    Task<List<string>> RetrieveAsync(string query, int? topK = null, CancellationToken ct = default);
    Task<string> AskAsync(string question, string? userId = null, CancellationToken ct = default);
}

public sealed class InMemoryRagContext : ICyRagContext
{
    private readonly CyAI _ai;
    private readonly string _provider;
    private readonly List<(string source, string chunk)> _chunks = new();
    private int _docs;

    public InMemoryRagContext(CyAI ai, string provider, string mode = "FileRag")
    {
        _ai = ai; _provider = provider; Mode = mode;
    }

    public string Mode { get; }
    public string EmbeddingProvider => "InMemory-BM25";
    public int IndexedChunks => _chunks.Count;
    public int IngestedDocuments => _docs;

    public Task IngestTextAsync(string text, string? sourceId = null, CancellationToken ct = default)
    {
        foreach (var ch in Chunk(text, 400))
            _chunks.Add((sourceId ?? "text", ch));
        _docs++;
        return Task.CompletedTask;
    }

    public async Task IngestFileAsync(string filePath, CancellationToken ct = default)
        => await IngestTextAsync(await File.ReadAllTextAsync(filePath, ct), Path.GetFileName(filePath), ct);

    public Task<List<string>> RetrieveAsync(string query, int? topK = null, CancellationToken ct = default)
    {
        var k = topK ?? 5;
        var terms = query.ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var ranked = _chunks
            .Select(c => (c.chunk, score: terms.Sum(t => CountOccurrences(c.chunk.ToLowerInvariant(), t))))
            .Where(x => x.score > 0)
            .OrderByDescending(x => x.score)
            .Take(k)
            .Select(x => x.chunk)
            .ToList();
        return Task.FromResult(ranked);
    }

    public async Task<string> AskAsync(string question, string? userId = null, CancellationToken ct = default)
    {
        var ctx = await RetrieveAsync(question, 5, ct);
        var augmented = $"Context:\n{string.Join("\n---\n", ctx)}\n\nQuestion: {question}";
        var resp = await _ai.Ask(augmented, _provider, userId ?? "rag-user", ct);
        return resp.Response;
    }

    private static IEnumerable<string> Chunk(string text, int size)
    {
        for (int i = 0; i < text.Length; i += size)
            yield return text.Substring(i, Math.Min(size, text.Length - i));
    }

    private static int CountOccurrences(string s, string t)
    {
        if (string.IsNullOrEmpty(t)) return 0;
        int n = 0, idx = 0;
        while ((idx = s.IndexOf(t, idx, StringComparison.Ordinal)) != -1) { n++; idx += t.Length; }
        return n;
    }

    public void Dispose() => _chunks.Clear();
}
