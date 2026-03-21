using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Crypto.Pqc;
using CyTypes.Core.Policy;
using CyTypes.Core.Security;
using CyTypes.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace CyTypes.DependencyInjection;

/// <summary>
/// Extension methods for registering CyTypes services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class CyTypesServiceCollectionExtensions
{
    /// <summary>
    /// Registers CyTypes core services including the default security policy, crypto engine,
    /// security auditor, and optionally the redacting logger provider.
    /// </summary>
    public static IServiceCollection AddCyTypes(this IServiceCollection services, Action<CyTypesOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new CyTypesOptions();
        configure?.Invoke(options);

        // Core services
        services.TryAddSingleton(options.DefaultPolicy);
        services.TryAddSingleton<ICryptoEngine, AesGcmEngine>();
        services.TryAddSingleton<SecurityAuditor>();

        // Secure buffer pool
        services.TryAddSingleton(new CyTypes.Core.Memory.SecureBufferPool(
            options.SecureBufferPoolSize > 0 ? options.SecureBufferPoolSize : 4096));

        // Audit sinks — collect all registered IAuditSink implementations
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuditSink, LoggingAuditSink>());

        // PQC key encapsulation
        if (options.EnablePqcKeyEncapsulation)
        {
            services.TryAddSingleton<IPqcKeyEncapsulation, MlKemKeyEncapsulation>();
        }

        // Redacting logger
        if (options.EnableRedactingLogger)
        {
            services.TryAddSingleton<RedactingLoggerProvider>(sp =>
            {
                var inner = sp.GetRequiredService<ILoggerFactory>();
                return new RedactingLoggerProvider(new FrameworkLoggerProvider(inner));
            });
        }

        return services;
    }

    /// <summary>
    /// Registers FHE services. Call this after <see cref="AddCyTypes"/> to enable
    /// homomorphic encryption support. Requires the CyTypes.Fhe package.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configureFheEngine">
    /// A factory that creates and configures the <see cref="IFheEngine"/> instance.
    /// This allows the caller to initialize the SEAL key manager and engine.
    /// </param>
    public static IServiceCollection AddCyTypesFhe(
        this IServiceCollection services,
        Func<IServiceProvider, IFheEngine> configureFheEngine)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureFheEngine);

        services.TryAddSingleton(sp =>
        {
            var engine = configureFheEngine(sp);
            // Configure the static provider so CyTypeBase instances can access the engine
            Primitives.Shared.FheEngineProvider.Configure(engine);
            return engine;
        });

        return services;
    }

    /// <summary>
    /// Minimal <see cref="ILoggerProvider"/> adapter that delegates to <see cref="ILoggerFactory"/>.
    /// Used to wrap the host's logging pipeline under the redacting layer.
    /// </summary>
    private sealed class FrameworkLoggerProvider(ILoggerFactory factory) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => factory.CreateLogger(categoryName);
        public void Dispose() { }
    }
}
