using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyDecimal"/>.
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyDecimal"/> that is encrypted with a new key.
/// </summary>
public sealed class CyDecimalJsonConverter : JsonConverter<CyDecimal>
{
    /// <inheritdoc/>
    public override CyDecimal Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException($"Expected a number token for CyDecimal, got {reader.TokenType}.");
        }

        var value = reader.GetDecimal();
        return new CyDecimal(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyDecimal value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.ToInsecureValue());
    }
}
