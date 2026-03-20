using System.Text.Json;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// Extension methods for registering CyTypes JSON converters with <see cref="JsonSerializerOptions"/>.
/// </summary>
public static class CyTypesJsonExtensions
{
    /// <summary>
    /// Adds all CyTypes primitive JSON converters to the specified <see cref="JsonSerializerOptions"/>.
    /// <para>
    /// <strong>Security note:</strong> Serialization decrypts values via
    /// <c>ToInsecureValue()</c> and marks each instance as compromised.
    /// Deserialization creates fresh instances encrypted with new keys.
    /// </para>
    /// </summary>
    /// <param name="options">The serializer options to configure.</param>
    /// <returns>The same <paramref name="options"/> instance for chaining.</returns>
    public static JsonSerializerOptions AddCyTypesConverters(this JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.Converters.Add(new CyIntJsonConverter());
        options.Converters.Add(new CyLongJsonConverter());
        options.Converters.Add(new CyFloatJsonConverter());
        options.Converters.Add(new CyDoubleJsonConverter());
        options.Converters.Add(new CyDecimalJsonConverter());
        options.Converters.Add(new CyBoolJsonConverter());
        options.Converters.Add(new CyStringJsonConverter());
        options.Converters.Add(new CyBytesJsonConverter());
        options.Converters.Add(new CyGuidJsonConverter());
        options.Converters.Add(new CyDateTimeJsonConverter());

        return options;
    }
}
