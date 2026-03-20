using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyString"/>.
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyString"/> that is encrypted with a new key.
/// Null JSON values are round-tripped as null (no CyString instance is created).
/// </summary>
public sealed class CyStringJsonConverter : JsonConverter<CyString?>
{
    /// <inheritdoc/>
    public override CyString? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a string or null token for CyString, got {reader.TokenType}.");
        }

        var value = reader.GetString();
        if (value is null)
        {
            return null;
        }

        return new CyString(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyString? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteStringValue(value.ToInsecureValue());
    }
}
