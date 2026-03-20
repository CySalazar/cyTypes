using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyInt"/>.
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyInt"/> that is encrypted with a new key.
/// </summary>
public sealed class CyIntJsonConverter : JsonConverter<CyInt>
{
    /// <inheritdoc/>
    public override CyInt Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException($"Expected a number token for CyInt, got {reader.TokenType}.");
        }

        var value = reader.GetInt32();
        return new CyInt(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyInt value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.ToInsecureValue());
    }
}
