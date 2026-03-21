using System.Text.Json;
using CyTypes.Primitives;
using CyTypes.Primitives.Serialization;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class JsonSerializationTests
{
    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions();
        options.AddCyTypesConverters();
        return options;
    }

    [Fact]
    public void CyInt_round_trip_serialize_to_JSON_number_and_back()
    {
        var options = CreateOptions();
        using var original = new CyInt(42);

        var json = JsonSerializer.Serialize(original, options);
        json.Should().Be("42");

        using var deserialized = JsonSerializer.Deserialize<CyInt>(json, options)!;
        deserialized.ToInsecureInt().Should().Be(42);
    }

    [Fact]
    public void CyString_round_trip()
    {
        var options = CreateOptions();
        using var original = new CyString("hello world");

        var json = JsonSerializer.Serialize<CyString?>(original, options);
        json.Should().Be("\"hello world\"");

        using var deserialized = JsonSerializer.Deserialize<CyString?>(json, options)!;
        deserialized.ToInsecureString().Should().Be("hello world");
    }

    [Fact]
    public void CyBool_round_trip()
    {
        var options = CreateOptions();
        using var original = new CyBool(true);

        var json = JsonSerializer.Serialize(original, options);
        json.Should().Be("true");

        using var deserialized = JsonSerializer.Deserialize<CyBool>(json, options)!;
        deserialized.ToInsecureBool().Should().BeTrue();
    }

    [Fact]
    public void CyDouble_round_trip()
    {
        var options = CreateOptions();
        using var original = new CyDouble(3.14);

        var json = JsonSerializer.Serialize(original, options);

        using var deserialized = JsonSerializer.Deserialize<CyDouble>(json, options)!;
        deserialized.ToInsecureDouble().Should().Be(3.14);
    }

    [Fact]
    public void CyGuid_round_trip()
    {
        var options = CreateOptions();
        var guid = Guid.NewGuid();
        using var original = new CyGuid(guid);

        var json = JsonSerializer.Serialize(original, options);
        json.Should().Contain(guid.ToString());

        using var deserialized = JsonSerializer.Deserialize<CyGuid>(json, options)!;
        deserialized.ToInsecureGuid().Should().Be(guid);
    }

    [Fact]
    public void CyDateTime_round_trip()
    {
        var options = CreateOptions();
        var dt = new DateTime(2024, 6, 15, 12, 30, 0, DateTimeKind.Utc);
        using var original = new CyDateTime(dt);

        var json = JsonSerializer.Serialize(original, options);

        using var deserialized = JsonSerializer.Deserialize<CyDateTime>(json, options)!;
        deserialized.ToInsecureDateTime().Should().BeCloseTo(dt, TimeSpan.FromMilliseconds(1));
    }

    [Fact]
    public void CyBytes_round_trip_as_base64()
    {
        var options = CreateOptions();
        var data = new byte[] { 1, 2, 3, 4, 5 };
        using var original = new CyBytes(data);

        var json = JsonSerializer.Serialize<CyBytes?>(original, options);
        // Should be a base64 string
        var expectedBase64 = Convert.ToBase64String(data);
        json.Should().Be($"\"{expectedBase64}\"");

        using var deserialized = JsonSerializer.Deserialize<CyBytes?>(json, options)!;
        deserialized.ToInsecureBytes().Should().Equal(data);
    }

    [Fact]
    public void AddCyTypesConverters_extension_method_registers_converters()
    {
        var options = new JsonSerializerOptions();

        var returned = options.AddCyTypesConverters();

        returned.Should().BeSameAs(options);
        options.Converters.Should().HaveCountGreaterOrEqualTo(10);
    }

    [Fact]
    public void CyString_null_handling_serializes_as_null()
    {
        var options = CreateOptions();
        CyString? nullValue = null;

        var json = JsonSerializer.Serialize(nullValue, options);
        json.Should().Be("null");

        var deserialized = JsonSerializer.Deserialize<CyString?>(json, options);
        deserialized.Should().BeNull();
    }

    [Fact]
    public void CyDecimal_round_trip()
    {
        var options = CreateOptions();
        using var original = new CyDecimal(99.99m);

        var json = JsonSerializer.Serialize(original, options);

        using var deserialized = JsonSerializer.Deserialize<CyDecimal>(json, options)!;
        deserialized.ToInsecureDecimal().Should().Be(99.99m);
    }

    [Fact]
    public void CyFloat_round_trip()
    {
        var options = CreateOptions();
        using var original = new CyFloat(2.71f);

        var json = JsonSerializer.Serialize(original, options);

        using var deserialized = JsonSerializer.Deserialize<CyFloat>(json, options)!;
        deserialized.ToInsecureFloat().Should().Be(2.71f);
    }

    [Fact]
    public void CyLong_round_trip()
    {
        var options = CreateOptions();
        using var original = new CyLong(9876543210L);

        var json = JsonSerializer.Serialize(original, options);
        json.Should().Be("9876543210");

        using var deserialized = JsonSerializer.Deserialize<CyLong>(json, options)!;
        deserialized.ToInsecureLong().Should().Be(9876543210L);
    }

    [Fact]
    public void CyDecimal_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyDecimal>("\"not a number\"", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyFloat_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyFloat>("\"not a number\"", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyLong_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyLong>("\"not a number\"", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyInt_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyInt>("\"not a number\"", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyDouble_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyDouble>("\"not a number\"", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyBool_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyBool>("42", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyGuid_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyGuid>("42", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyBytes_null_handling()
    {
        var options = CreateOptions();
        CyBytes? nullValue = null;
        var json = JsonSerializer.Serialize(nullValue, options);
        json.Should().Be("null");

        var deserialized = JsonSerializer.Deserialize<CyBytes?>(json, options);
        deserialized.Should().BeNull();
    }

    [Fact]
    public void CyDateTime_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyDateTime>("42", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyBytes_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyBytes>("42", options);
        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void CyString_deserialize_wrong_token_throws()
    {
        var options = CreateOptions();
        var act = () => JsonSerializer.Deserialize<CyString>("42", options);
        act.Should().Throw<JsonException>();
    }
}
