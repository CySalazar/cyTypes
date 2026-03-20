using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyBool"/>.
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyBool"/> that is encrypted with a new key.
/// </summary>
public sealed class CyBoolJsonConverter : JsonConverter<CyBool>
{
    /// <inheritdoc/>
    public override CyBool Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is not JsonTokenType.True and not JsonTokenType.False)
        {
            throw new JsonException($"Expected a boolean token for CyBool, got {reader.TokenType}.");
        }

        var value = reader.GetBoolean();
        return new CyBool(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyBool value, JsonSerializerOptions options)
    {
        writer.WriteBooleanValue(value.ToInsecureValue());
    }
}
