using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Crypto.KeyExchange;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CyTypes.Streams.DependencyInjection;

/// <summary>
/// Extension methods for registering CyTypes.Streams services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers CyTypes.Streams services including the chunked crypto engine factory
    /// and session key negotiator.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddCyTypesStreams(this IServiceCollection services)
    {
        services.TryAddTransient<SessionKeyNegotiator>();
        return services;
    }
}
