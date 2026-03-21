using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;

namespace CyTypes.Benchmarks.Application.Api;

public class CryptoApiHostFixture : WebApplicationFactory<CryptoApiHostFixture>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureWebHost(webHost =>
        {
            webHost.UseUrls("http://127.0.0.1:0");
            webHost.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapPost("/encrypt", async context =>
                    {
                        using var reader = new StreamReader(context.Request.Body);
                        var plaintext = await reader.ReadToEndAsync();
                        var cy = new CyString(plaintext);
                        var insecure = cy.ToInsecureString();
                        cy.Dispose();
                        await context.Response.WriteAsync(insecure);
                    });

                    endpoints.MapPost("/encrypt-native", async context =>
                    {
                        using var reader = new StreamReader(context.Request.Body);
                        var plaintext = await reader.ReadToEndAsync();
                        await context.Response.WriteAsync(plaintext);
                    });

                    endpoints.MapPost("/roundtrip", async context =>
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
                });
            });
        });

        return base.CreateHost(builder);
    }
}
