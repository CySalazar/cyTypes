using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyIntEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyInt(42);
        using var b = new CyInt(42);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyInt(1);
        using var b = new CyInt(2);

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyInt(42);

        a.Equals((CyInt?)null).Should().BeFalse();
    }

    [Fact]
    public void Equals_object_delegates_correctly()
    {
        using var a = new CyInt(42);
        using var b = new CyInt(42);

        a.Equals((object)b).Should().BeTrue();
        a.Equals((object)"not a CyInt").Should().BeFalse();
    }

    [Fact]
    public void Equals_consistent_with_operator()
    {
        using var a = new CyInt(10);
        using var b = new CyInt(10);

        (a == b).Should().Be(a.Equals(b));
    }

    [Fact]
    public void Works_in_HashSet()
    {
        using var a = new CyInt(42);
        using var b = new CyInt(42);

        // Different instances have different InstanceIds, so HashSet treats them as different
        var set = new HashSet<CyInt> { a, b };
        set.Should().HaveCount(2);
    }
}

public sealed class CyLongEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyLong(100L);
        using var b = new CyLong(100L);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyLong(1L);
        using var b = new CyLong(2L);

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyLong(42L);

        a.Equals((CyLong?)null).Should().BeFalse();
    }

    [Fact]
    public void Equals_consistent_with_operator()
    {
        using var a = new CyLong(10L);
        using var b = new CyLong(10L);

        (a == b).Should().Be(a.Equals(b));
    }
}

public sealed class CyDoubleEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyDouble(3.14);
        using var b = new CyDouble(3.14);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyDouble(1.0);
        using var b = new CyDouble(2.0);

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyDouble(42.0);

        a.Equals((CyDouble?)null).Should().BeFalse();
    }
}

public sealed class CyFloatEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyFloat(3.14f);
        using var b = new CyFloat(3.14f);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyFloat(1.0f);
        using var b = new CyFloat(2.0f);

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyFloat(42.0f);

        a.Equals((CyFloat?)null).Should().BeFalse();
    }
}

public sealed class CyDecimalEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyDecimal(99.99m);
        using var b = new CyDecimal(99.99m);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyDecimal(1.0m);
        using var b = new CyDecimal(2.0m);

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyDecimal(42.0m);

        a.Equals((CyDecimal?)null).Should().BeFalse();
    }
}

public sealed class CyBoolEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyBool(true);
        using var b = new CyBool(true);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyBool(true);
        using var b = new CyBool(false);

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyBool(true);

        a.Equals((CyBool?)null).Should().BeFalse();
    }

    [Fact]
    public void Equals_consistent_with_operator()
    {
        using var a = new CyBool(false);
        using var b = new CyBool(false);

        (a == b).Should().Be(a.Equals(b));
    }
}

public sealed class CyStringEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyString("hello");
        using var b = new CyString("hello");

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyString("hello");
        using var b = new CyString("world");

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyString("test");

        a.Equals((CyString?)null).Should().BeFalse();
    }

    [Fact]
    public void Equals_consistent_with_operator()
    {
        using var a = new CyString("abc");
        using var b = new CyString("abc");

        (a == b).Should().Be(a.Equals(b));
    }
}

public sealed class CyBytesEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        using var a = new CyBytes(new byte[] { 1, 2, 3 });
        using var b = new CyBytes(new byte[] { 1, 2, 3 });

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyBytes(new byte[] { 1, 2, 3 });
        using var b = new CyBytes(new byte[] { 4, 5, 6 });

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyBytes(new byte[] { 1 });

        a.Equals((CyBytes?)null).Should().BeFalse();
    }
}

public sealed class CyGuidEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        var guid = Guid.NewGuid();
        using var a = new CyGuid(guid);
        using var b = new CyGuid(guid);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyGuid(Guid.NewGuid());
        using var b = new CyGuid(Guid.NewGuid());

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyGuid(Guid.NewGuid());

        a.Equals((CyGuid?)null).Should().BeFalse();
    }
}

public sealed class CyDateTimeEquatableTests
{
    [Fact]
    public void Equals_same_value_returns_true()
    {
        var dt = new DateTime(2024, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        using var a = new CyDateTime(dt);
        using var b = new CyDateTime(dt);

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_different_value_returns_false()
    {
        using var a = new CyDateTime(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        using var b = new CyDateTime(new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_null_returns_false()
    {
        using var a = new CyDateTime(DateTime.UtcNow);

        a.Equals((CyDateTime?)null).Should().BeFalse();
    }

    [Fact]
    public void Equals_consistent_with_operator()
    {
        var dt = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        using var a = new CyDateTime(dt);
        using var b = new CyDateTime(dt);

        (a == b).Should().Be(a.Equals(b));
    }
}
