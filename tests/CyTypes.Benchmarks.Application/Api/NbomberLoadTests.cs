using System.Net.Http;
using System.Text;
using NBomber.Contracts;
using NBomber.CSharp;
using NBomber.Http.CSharp;

namespace CyTypes.Benchmarks.Application.Api;

/// <summary>
/// NBomber load tests for API endpoints using CyTypes.
/// Run manually with: dotnet run -- --filter *NBomber*
/// </summary>
public static class NbomberLoadTests
{
    public static void RunLoadTest(string baseUrl, int durationSeconds = 30)
    {
        using var httpClient = new HttpClient { BaseAddress = new Uri(baseUrl) };

        var encryptedScenario = Scenario.Create("encrypted_endpoint", async context =>
        {
            var request = Http.CreateRequest("POST", "/encrypt")
                .WithBody(new StringContent("load-test-payload-data", Encoding.UTF8, "text/plain"));

            var response = await Http.Send(httpClient, request);
            return response;
        })
        .WithLoadSimulations(
            Simulation.Inject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(durationSeconds)),
            Simulation.Inject(rate: 500, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(durationSeconds)),
            Simulation.Inject(rate: 1000, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(durationSeconds))
        );

        var nativeScenario = Scenario.Create("native_endpoint", async context =>
        {
            var request = Http.CreateRequest("POST", "/encrypt-native")
                .WithBody(new StringContent("load-test-payload-data", Encoding.UTF8, "text/plain"));

            var response = await Http.Send(httpClient, request);
            return response;
        })
        .WithLoadSimulations(
            Simulation.Inject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(durationSeconds)),
            Simulation.Inject(rate: 500, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(durationSeconds)),
            Simulation.Inject(rate: 1000, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(durationSeconds))
        );

        NBomberRunner
            .RegisterScenarios(encryptedScenario, nativeScenario)
            .Run();
    }
}
