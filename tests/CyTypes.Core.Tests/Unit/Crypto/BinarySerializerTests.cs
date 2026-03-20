using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Crypto;

public sealed class BinarySerializerTests
{
    private readonly BinarySerializer _sut = new();

    [Fact]
    public void Roundtrip_int()
    {
        var bytes = _sut.Serialize(42);
        _sut.Deserialize<int>(bytes).Should().Be(42);
    }

    [Fact]
    public void Roundtrip_long()
    {
        var bytes = _sut.Serialize(123456789L);
        _sut.Deserialize<long>(bytes).Should().Be(123456789L);
    }

    [Fact]
    public void Roundtrip_double()
    {
        var bytes = _sut.Serialize(3.14);
        _sut.Deserialize<double>(bytes).Should().Be(3.14);
    }

    [Fact]
    public void Roundtrip_float()
    {
        var bytes = _sut.Serialize(2.71f);
        _sut.Deserialize<float>(bytes).Should().Be(2.71f);
    }

    [Fact]
    public void Roundtrip_decimal()
    {
        var bytes = _sut.Serialize(99.99m);
        _sut.Deserialize<decimal>(bytes).Should().Be(99.99m);
    }

    [Fact]
    public void Roundtrip_bool_true()
    {
        var bytes = _sut.Serialize(true);
        _sut.Deserialize<bool>(bytes).Should().BeTrue();
    }

    [Fact]
    public void Roundtrip_bool_false()
    {
        var bytes = _sut.Serialize(false);
        _sut.Deserialize<bool>(bytes).Should().BeFalse();
    }

    [Fact]
    public void Roundtrip_string()
    {
        var bytes = _sut.Serialize("hello world");
        _sut.Deserialize<string>(bytes).Should().Be("hello world");
    }

    [Fact]
    public void Roundtrip_byte_array()
    {
        var original = new byte[] { 1, 2, 3, 4 };
        var bytes = _sut.Serialize(original);
        _sut.Deserialize<byte[]>(bytes).Should().BeEquivalentTo(original);
    }

    [Fact]
    public void Roundtrip_guid()
    {
        var guid = Guid.NewGuid();
        var bytes = _sut.Serialize(guid);
        _sut.Deserialize<Guid>(bytes).Should().Be(guid);
    }

    [Fact]
    public void Roundtrip_datetime()
    {
        var dt = new DateTime(2024, 6, 15, 14, 30, 0, DateTimeKind.Utc);
        var bytes = _sut.Serialize(dt);
        _sut.Deserialize<DateTime>(bytes).Ticks.Should().Be(dt.Ticks);
    }

    [Fact]
    public void Deserialize_short_int_throws()
    {
        var act = () => _sut.Deserialize<int>(new byte[3]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_short_long_throws()
    {
        var act = () => _sut.Deserialize<long>(new byte[7]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_short_double_throws()
    {
        var act = () => _sut.Deserialize<double>(new byte[7]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_short_float_throws()
    {
        var act = () => _sut.Deserialize<float>(new byte[3]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_short_decimal_throws()
    {
        var act = () => _sut.Deserialize<decimal>(new byte[15]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_short_guid_throws()
    {
        var act = () => _sut.Deserialize<Guid>(new byte[15]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_short_datetime_throws()
    {
        var act = () => _sut.Deserialize<DateTime>(new byte[7]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Deserialize_bool_empty_throws()
    {
        var act = () => _sut.Deserialize<bool>(ReadOnlySpan<byte>.Empty);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Unsupported_type_serialize_throws()
    {
        var act = () => _sut.Serialize(new object());
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Unsupported_type_deserialize_throws()
    {
        var act = () => _sut.Deserialize<object>(new byte[] { 1 });
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Serialize_byte_array_clones_input()
    {
        var original = new byte[] { 1, 2, 3, 4 };
        var serialized = _sut.Serialize(original);

        // Mutate the original array after serialization
        original[0] = 0xFF;
        original[1] = 0xFF;

        // Deserialize and verify the serialized data is unchanged
        var deserialized = _sut.Deserialize<byte[]>(serialized);
        deserialized[0].Should().Be(1);
        deserialized[1].Should().Be(2);
    }

    [Fact]
    public void Deserialize_string_empty_returns_empty()
    {
        var serialized = _sut.Serialize(string.Empty);
        var result = _sut.Deserialize<string>(serialized);
        result.Should().BeEmpty();
    }

    [Fact]
    public void Deserialize_byte_array_empty_returns_empty()
    {
        var serialized = _sut.Serialize(Array.Empty<byte>());
        var result = _sut.Deserialize<byte[]>(serialized);
        result.Should().BeEmpty();
    }
}
