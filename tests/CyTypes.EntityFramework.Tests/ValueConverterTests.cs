using CyTypes.EntityFramework.Converters;
using CyTypes.Primitives;
using FluentAssertions;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Xunit;

namespace CyTypes.EntityFramework.Tests;

public sealed class ValueConverterTests
{
    private static TProvider RoundTrip<TCy, TProvider>(ValueConverter<TCy, TProvider> converter, TProvider input)
    {
        var toProvider = converter.ConvertToProviderExpression.Compile();
        var fromProvider = converter.ConvertFromProviderExpression.Compile();
        var cy = fromProvider(input);
        return toProvider(cy);
    }

    [Fact]
    public void CyInt_round_trip()
    {
        var result = RoundTrip(new CyIntValueConverter(), 42);
        result.Should().Be(42);
    }

    [Fact]
    public void CyLong_round_trip()
    {
        var result = RoundTrip(new CyLongValueConverter(), 123456789L);
        result.Should().Be(123456789L);
    }

    [Fact]
    public void CyFloat_round_trip()
    {
        var result = RoundTrip(new CyFloatValueConverter(), 3.14f);
        result.Should().Be(3.14f);
    }

    [Fact]
    public void CyDouble_round_trip()
    {
        var result = RoundTrip(new CyDoubleValueConverter(), 2.71828);
        result.Should().Be(2.71828);
    }

    [Fact]
    public void CyDecimal_round_trip()
    {
        var result = RoundTrip(new CyDecimalValueConverter(), 99.99m);
        result.Should().Be(99.99m);
    }

    [Fact]
    public void CyBool_true_round_trip()
    {
        var result = RoundTrip(new CyBoolValueConverter(), true);
        result.Should().BeTrue();
    }

    [Fact]
    public void CyBool_false_round_trip()
    {
        var result = RoundTrip(new CyBoolValueConverter(), false);
        result.Should().BeFalse();
    }

    [Fact]
    public void CyString_round_trip()
    {
        var result = RoundTrip(new CyStringValueConverter(), "hello");
        result.Should().Be("hello");
    }

    [Fact]
    public void CyGuid_round_trip()
    {
        var guid = Guid.NewGuid();
        var result = RoundTrip(new CyGuidValueConverter(), guid);
        result.Should().Be(guid);
    }

    [Fact]
    public void CyDateTime_round_trip()
    {
        var dt = new DateTime(2025, 6, 15, 10, 30, 0, DateTimeKind.Utc);
        var result = RoundTrip(new CyDateTimeValueConverter(), dt);
        result.Should().Be(dt);
    }

    [Fact]
    public void CyBytes_round_trip()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5 };
        var result = RoundTrip(new CyBytesValueConverter(), bytes);
        result.Should().Equal(bytes);
    }

    [Fact]
    public void CyString_empty_string_round_trip()
    {
        var result = RoundTrip(new CyStringValueConverter(), "");
        result.Should().BeEmpty();
    }

    [Fact]
    public void CyBytes_empty_array_round_trip()
    {
        var result = RoundTrip(new CyBytesValueConverter(), Array.Empty<byte>());
        result.Should().BeEmpty();
    }
}
