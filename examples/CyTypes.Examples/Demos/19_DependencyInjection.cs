using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Policy;
using CyTypes.DependencyInjection;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CyTypes.Examples.Demos;

public static class DependencyInjectionDemo
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 19: ASP.NET Core Dependency Injection + Redacting Logger");

        ConsoleHelpers.PrintNote("AddCyTypes() registers core services: default policy, crypto engine, auditor.");
        ConsoleHelpers.PrintNote("EnableRedactingLogger strips encrypted payloads from log output.");
        Console.WriteLine();

        // --- Basic DI setup ---
        ConsoleHelpers.PrintSubHeader("Basic Registration");

        ConsoleHelpers.PrintCode("services.AddCyTypes(options => {");
        ConsoleHelpers.PrintCode("    options.DefaultPolicy = SecurityPolicy.Balanced;");
        ConsoleHelpers.PrintCode("    options.EnableRedactingLogger = true;");
        ConsoleHelpers.PrintCode("    options.EnablePqcKeyEncapsulation = true;");
        ConsoleHelpers.PrintCode("});");

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.SetMinimumLevel(LogLevel.Debug));
        services.AddSingleton<ILogger>(sp =>
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("CyTypes"));
        services.AddCyTypes(options =>
        {
            options.DefaultPolicy = SecurityPolicy.Balanced;
            options.EnableRedactingLogger = true;
            options.EnablePqcKeyEncapsulation = true;
        });

        using var provider = services.BuildServiceProvider();
        ConsoleHelpers.PrintSecure("Service provider built successfully.");
        Console.WriteLine();

        // --- Resolve services ---
        ConsoleHelpers.PrintSubHeader("Resolved Services");

        var policy = provider.GetRequiredService<SecurityPolicy>();
        ConsoleHelpers.PrintInfo($"Default policy: {policy}");

        var cryptoEngine = provider.GetRequiredService<ICryptoEngine>();
        ConsoleHelpers.PrintInfo($"Crypto engine: {cryptoEngine.GetType().Name}");

        var hasAuditor = provider.GetService<CyTypes.Core.Security.SecurityAuditor>() != null;
        ConsoleHelpers.PrintInfo($"Security auditor registered: {hasAuditor}");

        var hasPqc = provider.GetService<IPqcKeyEncapsulation>() != null;
        ConsoleHelpers.PrintInfo($"PQC key encapsulation registered: {hasPqc}");
        Console.WriteLine();

        // --- Redacting logger in action ---
        ConsoleHelpers.PrintSubHeader("Redacting Logger");

        ConsoleHelpers.PrintNote("The redacting logger strips hex payloads and base64 blobs from log messages,");
        ConsoleHelpers.PrintNote("preventing accidental exposure of encrypted data in log files.");
        Console.WriteLine();

        using var secret = new CyString("my-api-key-12345");
        string rawMessage = $"Processing request with token: {secret}";

        ConsoleHelpers.PrintCode("logger.LogInformation($\"Processing request with token: {secret}\");");
        ConsoleHelpers.PrintInfo($"Raw message:     {rawMessage}");

        string redacted = CyTypes.Logging.RedactingLogger.RedactCyTypes(rawMessage);
        ConsoleHelpers.PrintSecure($"Redacted output: {redacted}");
        ConsoleHelpers.PrintNote("Encrypted metadata and hex payloads are automatically stripped.");
        Console.WriteLine();

        // --- Configuration options ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Available CyTypesOptions");
        ConsoleHelpers.PrintInfo("DefaultPolicy             — SecurityPolicy for new instances");
        ConsoleHelpers.PrintInfo("EnableRedactingLogger     — Auto-redact CyType data from logs");
        ConsoleHelpers.PrintInfo("EnableAudit               — Security event tracking");
        ConsoleHelpers.PrintInfo("EnablePqcKeyEncapsulation — ML-KEM-1024 key exchange");
        ConsoleHelpers.PrintInfo("SecureBufferPoolSize      — Buffer pool allocation size");
        Console.WriteLine();

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("DI integration makes cyTypes a first-class citizen in ASP.NET Core.");
    }
}
