using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.AI.Provider;

public sealed class ProviderCallResult
{
    public string Text { get; init; } = "";
    public int InputTokens { get; init; }
    public int OutputTokens { get; init; }
    public decimal EstimatedCost { get; init; }
}

/// <summary>
/// Single turn in a multi-turn chat request. Mirrors the shape CyTypes.AI
/// provider implementations speak natively without depending on any higher
/// layer (CySecurity.Core's <c>CyAiMessage</c> is a parallel type and the
/// caller converts between the two).
/// </summary>
public readonly record struct ChatMessage(string Role, string Content);

public interface IAIProvider
{
    string Name { get; }
    string Model { get; }

    /// <summary>
    /// Legacy single-turn completion. Preserved for backwards compatibility —
    /// the gateway still routes single-prompt callers here.
    /// </summary>
    Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default);

    /// <summary>
    /// Multi-turn completion. Every provider serializes the list into its
    /// native chat API shape (Anthropic/OpenAI/OpenRouter: <c>messages[]</c>,
    /// Google: <c>contents[]</c> + <c>systemInstruction</c>, Ollama:
    /// <c>/api/chat</c>). Implementations MUST NOT ignore the list — otherwise
    /// conversation history is silently dropped.
    /// </summary>
    /// <param name="messages">Ordered conversation turns (role/content).</param>
    /// <param name="systemPrompt">Optional system prompt, handled out-of-band where the provider supports it.</param>
    /// <param name="ct">Cancellation token for the HTTP call.</param>
    Task<ProviderCallResult> CompleteAsync(
        IReadOnlyList<ChatMessage> messages,
        string? systemPrompt,
        CancellationToken ct = default);
}

public abstract class ProviderOptionsBase
{
    public string Model { get; set; } = "";
    public string? ApiKey { get; set; }
    public string? Endpoint { get; set; }
    public int MaxTokens { get; set; } = 1024;
    public HttpClient? HttpClient { get; set; }
}

public sealed class AnthropicOptions : ProviderOptionsBase { public AnthropicOptions() { Model = "claude-sonnet-4-20250514"; } }
public sealed class OpenAIOptions : ProviderOptionsBase { public OpenAIOptions() { Model = "gpt-4o-mini"; } }
public sealed class GoogleOptions : ProviderOptionsBase { public GoogleOptions() { Model = "gemini-2.5-flash"; } }
public sealed class OpenRouterOptions : ProviderOptionsBase { public OpenRouterOptions() { Model = "google/gemini-3.1-flash-lite-preview"; } }
public sealed class OllamaOptions : ProviderOptionsBase { public OllamaOptions() { Model = "llama3.1"; Endpoint = "http://localhost:11434"; } }

internal static class HttpFactory
{
    private static readonly HttpClient _shared = new() { Timeout = TimeSpan.FromSeconds(120) };
    public static HttpClient Get(ProviderOptionsBase o) => o.HttpClient ?? _shared;
}

public sealed class AnthropicProvider : IAIProvider
{
    private readonly AnthropicOptions _o;
    public AnthropicProvider(AnthropicOptions o) { _o = o; _o.ApiKey ??= Environment.GetEnvironmentVariable("CYSECURITY_ANTHROPIC_API_KEY"); }
    public string Name => "anthropic";
    public string Model => _o.Model;

    public Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
        => CompleteAsync(new[] { new ChatMessage("user", prompt) }, systemPrompt: null, ct);

    public async Task<ProviderCallResult> CompleteAsync(
        IReadOnlyList<ChatMessage> messages,
        string? systemPrompt,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_o.ApiKey)) throw new InvalidOperationException("Anthropic API key missing");
        var http = HttpFactory.Get(_o);
        var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages");
        req.Headers.Add("x-api-key", _o.ApiKey);
        req.Headers.Add("anthropic-version", "2023-06-01");

        // Anthropic forbids "system" messages inside messages[] — system prompt
        // goes to the top-level `system` field. Non-user/assistant roles coming
        // from the caller are folded into the system field for safety.
        var sysParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(systemPrompt)) sysParts.Add(systemPrompt!);
        var wire = new List<object>(messages.Count);
        foreach (var m in messages)
        {
            if (string.Equals(m.Role, "system", StringComparison.OrdinalIgnoreCase))
            {
                sysParts.Add(m.Content);
                continue;
            }
            wire.Add(new { role = m.Role, content = m.Content });
        }
        if (wire.Count == 0)
            wire.Add(new { role = "user", content = string.Empty });

        object payload = sysParts.Count > 0
            ? new { model = _o.Model, max_tokens = _o.MaxTokens, system = string.Join("\n\n", sysParts), messages = wire }
            : (object)new { model = _o.Model, max_tokens = _o.MaxTokens, messages = wire };

        req.Content = JsonContent.Create(payload);
        using var resp = await http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Anthropic {(int)resp.StatusCode}: {Truncate(body)}");
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString() ?? "";
        var inTok = doc.RootElement.GetProperty("usage").GetProperty("input_tokens").GetInt32();
        var outTok = doc.RootElement.GetProperty("usage").GetProperty("output_tokens").GetInt32();
        return new ProviderCallResult { Text = text, InputTokens = inTok, OutputTokens = outTok, EstimatedCost = (inTok * 3m + outTok * 15m) / 1_000_000m };
    }
    private static string Truncate(string s) => s.Length > 200 ? s[..200] + "..." : s;
}

internal static class ProviderHelpers
{
    internal static string Truncate(string s) => s.Length > 200 ? s[..200] + "..." : s;
}

public sealed class OpenAIProvider : IAIProvider
{
    private readonly OpenAIOptions _o;
    public OpenAIProvider(OpenAIOptions o) { _o = o; _o.ApiKey ??= Environment.GetEnvironmentVariable("CYSECURITY_OPENAI_API_KEY"); _o.Endpoint ??= "https://api.openai.com/v1"; }
    public string Name => "openai";
    public string Model => _o.Model;
    public Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
        => CompleteAsync(new[] { new ChatMessage("user", prompt) }, systemPrompt: null, ct);
    public Task<ProviderCallResult> CompleteAsync(IReadOnlyList<ChatMessage> messages, string? systemPrompt, CancellationToken ct = default)
        => OpenAICompat.CallAsync(_o, messages, systemPrompt, "openai", 0.15m, 0.6m, ct);
}

public sealed class OpenRouterProvider : IAIProvider
{
    private readonly OpenRouterOptions _o;
    public OpenRouterProvider(OpenRouterOptions o) { _o = o; _o.ApiKey ??= Environment.GetEnvironmentVariable("CYSECURITY_OPENROUTER_API_KEY"); _o.Endpoint ??= "https://openrouter.ai/api/v1"; }
    public string Name => "openrouter";
    public string Model => _o.Model;
    public Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
        => CompleteAsync(new[] { new ChatMessage("user", prompt) }, systemPrompt: null, ct);
    public Task<ProviderCallResult> CompleteAsync(IReadOnlyList<ChatMessage> messages, string? systemPrompt, CancellationToken ct = default)
        => OpenAICompat.CallAsync(_o, messages, systemPrompt, "openrouter", 0.5m, 1.5m, ct);
}

public sealed class OllamaProvider : IAIProvider
{
    private readonly OllamaOptions _o;
    public OllamaProvider(OllamaOptions o) { _o = o; }
    public string Name => "ollama";
    public string Model => _o.Model;

    public Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
        => CompleteAsync(new[] { new ChatMessage("user", prompt) }, systemPrompt: null, ct);

    public async Task<ProviderCallResult> CompleteAsync(
        IReadOnlyList<ChatMessage> messages,
        string? systemPrompt,
        CancellationToken ct = default)
    {
        var http = HttpFactory.Get(_o);

        // Use the chat endpoint so Ollama sees real multi-turn history
        // instead of a blob flattened into /api/generate.
        var wire = new List<object>(messages.Count + 1);
        if (!string.IsNullOrWhiteSpace(systemPrompt))
            wire.Add(new { role = "system", content = systemPrompt });
        foreach (var m in messages)
            wire.Add(new { role = m.Role, content = m.Content });

        var resp = await http.PostAsJsonAsync($"{_o.Endpoint}/api/chat",
            new { model = _o.Model, messages = wire, stream = false }, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Ollama {(int)resp.StatusCode}: {ProviderHelpers.Truncate(body)}");
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("message").GetProperty("content").GetString() ?? "";
        int approxIn = 0;
        foreach (var m in messages) approxIn += m.Content.Length / 4;
        return new ProviderCallResult { Text = text, InputTokens = approxIn, OutputTokens = text.Length / 4, EstimatedCost = 0m };
    }
}

public sealed class GoogleProvider : IAIProvider
{
    private readonly GoogleOptions _o;
    public GoogleProvider(GoogleOptions o) { _o = o; _o.ApiKey ??= Environment.GetEnvironmentVariable("CYSECURITY_GOOGLE_API_KEY"); }
    public string Name => "google";
    public string Model => _o.Model;

    public Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
        => CompleteAsync(new[] { new ChatMessage("user", prompt) }, systemPrompt: null, ct);

    public async Task<ProviderCallResult> CompleteAsync(
        IReadOnlyList<ChatMessage> messages,
        string? systemPrompt,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_o.ApiKey)) throw new InvalidOperationException("Google API key missing");
        var http = HttpFactory.Get(_o);
        var url = $"https://generativelanguage.googleapis.com/v1beta/models/{_o.Model}:generateContent";

        // Google uses roles "user" and "model" (not "assistant"). Normalize.
        var contents = new List<object>(messages.Count);
        foreach (var m in messages)
        {
            var role = string.Equals(m.Role, "assistant", StringComparison.OrdinalIgnoreCase) ? "model" : m.Role;
            if (string.Equals(role, "system", StringComparison.OrdinalIgnoreCase))
                continue; // system prompt is handled out of band
            contents.Add(new { role, parts = new[] { new { text = m.Content } } });
        }
        if (contents.Count == 0)
            contents.Add(new { role = "user", parts = new[] { new { text = string.Empty } } });

        object payload = !string.IsNullOrWhiteSpace(systemPrompt)
            ? new { contents, systemInstruction = new { parts = new[] { new { text = systemPrompt } } } }
            : (object)new { contents };

        // SECURITY: API key passed via header instead of URL query string to prevent
        // leakage in HTTP logs, proxy caches, and error messages.
        var req = new HttpRequestMessage(HttpMethod.Post, url);
        req.Headers.Add("x-goog-api-key", _o.ApiKey);
        req.Content = JsonContent.Create(payload);
        using var resp = await http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Google {(int)resp.StatusCode}: {ProviderHelpers.Truncate(body)}");
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("candidates")[0].GetProperty("content").GetProperty("parts")[0].GetProperty("text").GetString() ?? "";
        int approxIn = 0;
        foreach (var m in messages) approxIn += m.Content.Length / 4;
        return new ProviderCallResult { Text = text, InputTokens = approxIn, OutputTokens = text.Length / 4, EstimatedCost = 0m };
    }
}

internal static class OpenAICompat
{
    public static async Task<ProviderCallResult> CallAsync(
        ProviderOptionsBase o,
        IReadOnlyList<ChatMessage> messages,
        string? systemPrompt,
        string label,
        decimal inPer1k,
        decimal outPer1k,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(o.ApiKey)) throw new InvalidOperationException($"{label} API key missing");
        var http = HttpFactory.Get(o);
        var req = new HttpRequestMessage(HttpMethod.Post, $"{o.Endpoint}/chat/completions");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", o.ApiKey);

        var wire = new List<object>(messages.Count + 1);
        if (!string.IsNullOrWhiteSpace(systemPrompt))
            wire.Add(new { role = "system", content = systemPrompt });
        foreach (var m in messages)
            wire.Add(new { role = m.Role, content = m.Content });
        if (wire.Count == 0)
            wire.Add(new { role = "user", content = string.Empty });

        req.Content = JsonContent.Create(new
        {
            model = o.Model,
            max_tokens = o.MaxTokens,
            messages = wire
        });
        using var resp = await http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"{label} {(int)resp.StatusCode}: {ProviderHelpers.Truncate(body)}");
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? "";
        int inTok = 0, outTok = 0;
        if (doc.RootElement.TryGetProperty("usage", out var u))
        {
            inTok = u.TryGetProperty("prompt_tokens", out var pt) ? pt.GetInt32() : 0;
            outTok = u.TryGetProperty("completion_tokens", out var ot) ? ot.GetInt32() : 0;
        }
        return new ProviderCallResult { Text = text, InputTokens = inTok, OutputTokens = outTok, EstimatedCost = (inTok * inPer1k + outTok * outPer1k) / 1000m };
    }
}
