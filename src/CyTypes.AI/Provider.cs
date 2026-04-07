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

public interface IAIProvider
{
    string Name { get; }
    string Model { get; }
    Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default);
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
    public async Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_o.ApiKey)) throw new InvalidOperationException("Anthropic API key missing");
        var http = HttpFactory.Get(_o);
        var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages");
        req.Headers.Add("x-api-key", _o.ApiKey);
        req.Headers.Add("anthropic-version", "2023-06-01");
        req.Content = JsonContent.Create(new
        {
            model = _o.Model,
            max_tokens = _o.MaxTokens,
            messages = new[] { new { role = "user", content = prompt } }
        });
        using var resp = await http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Anthropic {(int)resp.StatusCode}: {Truncate(body)}");
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString() ?? "";
        var inTok = doc.RootElement.GetProperty("usage").GetProperty("input_tokens").GetInt32();
        var outTok = doc.RootElement.GetProperty("usage").GetProperty("output_tokens").GetInt32();
        return new ProviderCallResult { Text = text, InputTokens = inTok, OutputTokens = outTok, EstimatedCost = (inTok * 3m + outTok * 15m) / 1_000_000m };
    }
    private static string Truncate(string s) => s.Length > 200 ? s[..200] : s;
}

public sealed class OpenAIProvider : IAIProvider
{
    private readonly OpenAIOptions _o;
    public OpenAIProvider(OpenAIOptions o) { _o = o; _o.ApiKey ??= Environment.GetEnvironmentVariable("CYSECURITY_OPENAI_API_KEY"); _o.Endpoint ??= "https://api.openai.com/v1"; }
    public string Name => "openai";
    public string Model => _o.Model;
    public async Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
        => await OpenAICompat.CallAsync(_o, prompt, "openai", 0.15m, 0.6m, ct);
}

public sealed class OpenRouterProvider : IAIProvider
{
    private readonly OpenRouterOptions _o;
    public OpenRouterProvider(OpenRouterOptions o) { _o = o; _o.ApiKey ??= Environment.GetEnvironmentVariable("CYSECURITY_OPENROUTER_API_KEY"); _o.Endpoint ??= "https://openrouter.ai/api/v1"; }
    public string Name => "openrouter";
    public string Model => _o.Model;
    public Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
        => OpenAICompat.CallAsync(_o, prompt, "openrouter", 0.5m, 1.5m, ct);
}

public sealed class OllamaProvider : IAIProvider
{
    private readonly OllamaOptions _o;
    public OllamaProvider(OllamaOptions o) { _o = o; }
    public string Name => "ollama";
    public string Model => _o.Model;
    public async Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
    {
        var http = HttpFactory.Get(_o);
        var resp = await http.PostAsJsonAsync($"{_o.Endpoint}/api/generate",
            new { model = _o.Model, prompt, stream = false }, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Ollama {(int)resp.StatusCode}: {body}");
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("response").GetString() ?? "";
        return new ProviderCallResult { Text = text, InputTokens = prompt.Length / 4, OutputTokens = text.Length / 4, EstimatedCost = 0m };
    }
}

public sealed class GoogleProvider : IAIProvider
{
    private readonly GoogleOptions _o;
    public GoogleProvider(GoogleOptions o) { _o = o; _o.ApiKey ??= Environment.GetEnvironmentVariable("CYSECURITY_GOOGLE_API_KEY"); }
    public string Name => "google";
    public string Model => _o.Model;
    public async Task<ProviderCallResult> CompleteAsync(string prompt, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_o.ApiKey)) throw new InvalidOperationException("Google API key missing");
        var http = HttpFactory.Get(_o);
        var url = $"https://generativelanguage.googleapis.com/v1beta/models/{_o.Model}:generateContent?key={_o.ApiKey}";
        var resp = await http.PostAsJsonAsync(url, new
        {
            contents = new[] { new { parts = new[] { new { text = prompt } } } }
        }, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Google {(int)resp.StatusCode}: {body}");
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("candidates")[0].GetProperty("content").GetProperty("parts")[0].GetProperty("text").GetString() ?? "";
        return new ProviderCallResult { Text = text, InputTokens = prompt.Length / 4, OutputTokens = text.Length / 4, EstimatedCost = 0m };
    }
}

internal static class OpenAICompat
{
    public static async Task<ProviderCallResult> CallAsync(ProviderOptionsBase o, string prompt, string label, decimal inPer1k, decimal outPer1k, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(o.ApiKey)) throw new InvalidOperationException($"{label} API key missing");
        var http = HttpFactory.Get(o);
        var req = new HttpRequestMessage(HttpMethod.Post, $"{o.Endpoint}/chat/completions");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", o.ApiKey);
        req.Content = JsonContent.Create(new
        {
            model = o.Model,
            max_tokens = o.MaxTokens,
            messages = new[] { new { role = "user", content = prompt } }
        });
        using var resp = await http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"{label} {(int)resp.StatusCode}: {body}");
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
