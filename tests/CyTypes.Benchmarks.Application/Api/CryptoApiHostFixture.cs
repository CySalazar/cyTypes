using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;

namespace CyTypes.Benchmarks.Application.Api;

/// <summary>
/// Self-contained test fixture that hosts a minimal ASP.NET Core app with crypto endpoints.
/// Uses TestServer directly instead of WebApplicationFactory to avoid entry point discovery issues
/// when running inside BenchmarkDotNet's separate process.
/// </summary>
public class CryptoApiHostFixture : IDisposable
{
    private readonly WebApplication _app;

    public CryptoApiHostFixture()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        _app = builder.Build();

        _app.MapPost("/encrypt", async context =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var plaintext = await reader.ReadToEndAsync();
            using var cy = new CyString(plaintext);
            var insecure = cy.ToInsecureString();
            await context.Response.WriteAsync(insecure);
        });

        _app.MapPost("/encrypt-native", async context =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var plaintext = await reader.ReadToEndAsync();
            await context.Response.WriteAsync(plaintext);
        });

        _app.MapPost("/roundtrip", async context =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var plaintext = await reader.ReadToEndAsync();
            var engine = new AesGcmEngine();
            var key = new byte[32];
            RandomNumberGenerator.Fill(key);
            var ct = engine.Encrypt(System.Text.Encoding.UTF8.GetBytes(plaintext), key);
            var pt = engine.Decrypt(ct, key);
            await context.Response.WriteAsync(System.Text.Encoding.UTF8.GetString(pt));
        });

        _app.Start();
    }

    public HttpClient CreateClient() => _app.GetTestClient();

    public void Dispose()
    {
        _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        GC.SuppressFinalize(this);
    }
}
