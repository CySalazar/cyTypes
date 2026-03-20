using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyGuid"/>.
/// The GUID is serialized in standard "D" format (e.g. "d85b1407-351d-4694-9392-03acc5870eb1").
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyGuid"/> that is encrypted with a new key.
/// </summary>
public sealed class CyGuidJsonConverter : JsonConverter<CyGuid>
{
    /// <inheritdoc/>
    public override CyGuid Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a string token for CyGuid, got {reader.TokenType}.");
        }

        if (!reader.TryGetGuid(out var value))
        {
            throw new JsonException("The JSON string is not a valid GUID format.");
        }

        return new CyGuid(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyGuid value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToInsecureValue());
    }
}
