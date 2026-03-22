using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace CyTypes.Benchmarks.Application.Api;

[MemoryDiagnoser]
[SuppressMessage("Reliability", "CA1001:Types that own disposable fields should be disposable")]
public class ApiLatencyBenchmarks
{
    private CryptoApiHostFixture _fixture = null!;
    private HttpClient _client = null!;
    private StringContent _payload = null!;

    [GlobalSetup]
    public void Setup()
    {
        _fixture = new CryptoApiHostFixture();
        _client = _fixture.CreateClient();
        _payload = new StringContent("benchmark-test-payload-data-1234567890", Encoding.UTF8, "text/plain");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _client?.Dispose();
        _fixture?.Dispose();
    }

    [Benchmark]
    public async Task<string> EncryptedEndpoint()
    {
        var response = await _client.PostAsync("/encrypt",
            new StringContent("benchmark-test-payload-data-1234567890", Encoding.UTF8, "text/plain"));
        return await response.Content.ReadAsStringAsync();
    }

    [Benchmark(Baseline = true)]
    public async Task<string> NativeEndpoint()
    {
        var response = await _client.PostAsync("/encrypt-native",
            new StringContent("benchmark-test-payload-data-1234567890", Encoding.UTF8, "text/plain"));
        return await response.Content.ReadAsStringAsync();
    }

    [Benchmark]
    public async Task<string> RoundtripEndpoint()
    {
        var response = await _client.PostAsync("/roundtrip",
            new StringContent("benchmark-test-payload-data-1234567890", Encoding.UTF8, "text/plain"));
        return await response.Content.ReadAsStringAsync();
    }
}
