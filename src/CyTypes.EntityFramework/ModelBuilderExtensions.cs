using CyTypes.EntityFramework.Converters;
using CyTypes.Primitives;
using Microsoft.EntityFrameworkCore;

namespace CyTypes.EntityFramework;

/// <summary>
/// Extension methods for configuring CyTypes value converters on an EF Core <see cref="ModelConfigurationBuilder"/>.
/// </summary>
public static class ModelBuilderExtensions
{
    /// <summary>
    /// Registers EF Core value converters for all CyTypes encrypted primitives,
    /// enabling seamless persistence of always-encrypted types.
    /// </summary>
    /// <param name="configurationBuilder">The model configuration builder to configure.</param>
    /// <returns>The same <paramref name="configurationBuilder"/> instance for chaining.</returns>
    public static ModelConfigurationBuilder UseCyTypes(this ModelConfigurationBuilder configurationBuilder)
    {
        ArgumentNullException.ThrowIfNull(configurationBuilder);

        configurationBuilder.Properties<CyInt>().HaveConversion<CyIntValueConverter>();
        configurationBuilder.Properties<CyLong>().HaveConversion<CyLongValueConverter>();
        configurationBuilder.Properties<CyFloat>().HaveConversion<CyFloatValueConverter>();
        configurationBuilder.Properties<CyDouble>().HaveConversion<CyDoubleValueConverter>();
        configurationBuilder.Properties<CyDecimal>().HaveConversion<CyDecimalValueConverter>();
        configurationBuilder.Properties<CyBool>().HaveConversion<CyBoolValueConverter>();
        configurationBuilder.Properties<CyString>().HaveConversion<CyStringValueConverter>();
        configurationBuilder.Properties<CyGuid>().HaveConversion<CyGuidValueConverter>();
        configurationBuilder.Properties<CyDateTime>().HaveConversion<CyDateTimeValueConverter>();
        configurationBuilder.Properties<CyBytes>().HaveConversion<CyBytesValueConverter>();

        return configurationBuilder;
    }
}
