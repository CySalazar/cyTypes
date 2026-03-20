using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyFloat"/>.
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyFloat"/> that is encrypted with a new key.
/// </summary>
public sealed class CyFloatJsonConverter : JsonConverter<CyFloat>
{
    /// <inheritdoc/>
    public override CyFloat Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number)
        {
            throw new JsonException($"Expected a number token for CyFloat, got {reader.TokenType}.");
        }

        var value = reader.GetSingle();
        return new CyFloat(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyFloat value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.ToInsecureValue());
    }
}
