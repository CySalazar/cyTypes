using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;
using CyTypes.Core.Crypto.Pqc;
using CyTypes.Core.Policy;
using CyTypes.Core.Security;
using CyTypes.Logging;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CyTypes.DependencyInjection.Tests;

public sealed class ServiceRegistrationTests
{
    private static ServiceProvider BuildProvider(Action<CyTypesOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        // LoggingAuditSink requires non-generic ILogger; bridge it from the factory
        services.AddSingleton<ILogger>(sp => sp.GetRequiredService<ILoggerFactory>().CreateLogger("CyTypes.Audit"));
        services.AddCyTypes(configure);
        return services.BuildServiceProvider();
    }

    [Fact]
    public void AddCyTypes_registers_default_SecurityPolicy()
    {
        using var sp = BuildProvider();
        var policy = sp.GetRequiredService<SecurityPolicy>();
        policy.Should().Be(SecurityPolicy.Default);
    }

    [Fact]
    public void AddCyTypes_registers_AesGcmEngine_as_ICryptoEngine()
    {
        using var sp = BuildProvider();
        var engine = sp.GetRequiredService<ICryptoEngine>();
        engine.Should().BeOfType<AesGcmEngine>();
    }

    [Fact]
    public void AddCyTypes_registers_SecurityAuditor()
    {
        using var sp = BuildProvider();
        var auditor = sp.GetRequiredService<SecurityAuditor>();
        auditor.Should().NotBeNull();
    }

    [Fact]
    public void AddCyTypes_with_custom_policy_uses_configured_policy()
    {
        var custom = SecurityPolicy.Maximum;
        using var sp = BuildProvider(o => o.DefaultPolicy = custom);
        var policy = sp.GetRequiredService<SecurityPolicy>();
        policy.Should().Be(custom);
    }

    [Fact]
    public void AddCyTypes_with_PqcEnabled_registers_MlKemKeyEncapsulation()
    {
        using var sp = BuildProvider(o => o.EnablePqcKeyEncapsulation = true);
        var pqc = sp.GetRequiredService<IPqcKeyEncapsulation>();
        pqc.Should().BeOfType<MlKemKeyEncapsulation>();
    }

    [Fact]
    public void AddCyTypes_with_RedactingLogger_disabled_does_not_register_provider()
    {
        using var sp = BuildProvider(o => o.EnableRedactingLogger = false);
        var provider = sp.GetService<RedactingLoggerProvider>();
        provider.Should().BeNull();
    }

    [Fact]
    public void AddCyTypes_throws_on_null_services()
    {
        IServiceCollection services = null!;
        var act = () => services.AddCyTypes();
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddCyTypesFhe_throws_on_null_factory()
    {
        var services = new ServiceCollection();
        var act = () => services.AddCyTypesFhe(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddCyTypesFhe_throws_on_null_services()
    {
        IServiceCollection services = null!;
        var act = () => services.AddCyTypesFhe(_ => null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void CyTypesOptions_has_correct_defaults()
    {
        var options = new CyTypesOptions();

        options.DefaultPolicy.Should().Be(SecurityPolicy.Default);
        options.EnableRedactingLogger.Should().BeTrue();
        options.EnableAudit.Should().BeTrue();
        options.EnableFhe.Should().BeFalse();
        options.EnablePqcKeyEncapsulation.Should().BeFalse();
    }

    [Fact]
    public void AddCyTypes_without_PqcEnabled_does_not_register_IPqcKeyEncapsulation()
    {
        using var sp = BuildProvider();
        var pqc = sp.GetService<IPqcKeyEncapsulation>();
        pqc.Should().BeNull();
    }

    [Fact]
    public void AddCyTypes_with_RedactingLogger_enabled_registers_provider()
    {
        using var sp = BuildProvider(o => o.EnableRedactingLogger = true);
        var provider = sp.GetService<RedactingLoggerProvider>();
        provider.Should().NotBeNull();
    }

    [Fact]
    public void AddCyTypes_returns_same_service_collection()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ILogger>(sp => sp.GetRequiredService<ILoggerFactory>().CreateLogger("test"));
        var result = services.AddCyTypes();
        result.Should().BeSameAs(services);
    }
}
