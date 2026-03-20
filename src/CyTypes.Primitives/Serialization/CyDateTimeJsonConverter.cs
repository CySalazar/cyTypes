using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CyTypes.Primitives.Serialization;

/// <summary>
/// System.Text.Json converter for <see cref="CyDateTime"/>.
/// The DateTime is serialized as an ISO 8601 string (round-trip "O" format).
/// Serialization calls ToInsecureValue(), which
/// decrypts the value and marks the instance as compromised.
/// Deserialization creates a fresh <see cref="CyDateTime"/> that is encrypted with a new key.
/// </summary>
public sealed class CyDateTimeJsonConverter : JsonConverter<CyDateTime>
{
    private const string Iso8601Format = "O";

    /// <inheritdoc/>
    public override CyDateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a string token for CyDateTime, got {reader.TokenType}.");
        }

        var text = reader.GetString()
            ?? throw new JsonException("Expected a non-null ISO 8601 date string for CyDateTime.");

        if (!DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var value))
        {
            throw new JsonException($"The JSON string \"{text}\" is not a valid ISO 8601 DateTime.");
        }

        return new CyDateTime(value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CyDateTime value, JsonSerializerOptions options)
    {
        var dt = value.ToInsecureValue();
        writer.WriteStringValue(dt.ToString(Iso8601Format, CultureInfo.InvariantCulture));
    }
}
