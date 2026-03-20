using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyLong"/>.
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyLong"/> that is encrypted with a new key.
/// </summary>
public sealed class CyLongJsonConverter : JsonConverter<CyLong>
{
    /// <inheritdoc/>
    public override CyLong Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException($"Expected a number token for CyLong, got {reader.TokenType}.");
        }

        var value = reader.GetInt64();
        return new CyLong(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyLong value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.ToInsecureValue());
    }
}
