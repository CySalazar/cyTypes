using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyBytes"/>.
/// The byte array is serialized as a base64-encoded JSON string.
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyBytes"/> that is encrypted with a new key.
/// </summary>
public sealed class CyBytesJsonConverter : JsonConverter<CyBytes?>
{
    /// <inheritdoc/>
    public override CyBytes? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a base64 string or null token for CyBytes, got {reader.TokenType}.");
        }

        var bytes = reader.GetBytesFromBase64();
        return new CyBytes(bytes);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyBytes? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteBase64StringValue(value.ToInsecureValue());
    }
}
