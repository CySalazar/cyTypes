using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyIntComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_less_than()
    {
        using var a = new CyInt(1);
        using var b = new CyInt(10);

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyInt(42);
        using var b = new CyInt(42);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_greater_than()
    {
        using var a = new CyInt(100);
        using var b = new CyInt(1);

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyInt(42);

        a.CompareTo(null).Should().Be(1);
    }

    [Fact]
    public void LINQ_OrderBy_works_with_CyInt()
    {
        using var c = new CyInt(30);
        using var a = new CyInt(10);
        using var b = new CyInt(20);

        var sorted = new[] { c, a, b }.OrderBy(x => x).ToList();

        sorted[0].ToInsecureInt().Should().Be(10);
        sorted[1].ToInsecureInt().Should().Be(20);
        sorted[2].ToInsecureInt().Should().Be(30);
    }
}

public sealed class CyLongComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_less_than()
    {
        using var a = new CyLong(1L);
        using var b = new CyLong(10L);

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyLong(42L);
        using var b = new CyLong(42L);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_greater_than()
    {
        using var a = new CyLong(100L);
        using var b = new CyLong(1L);

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyLong(42L);

        a.CompareTo(null).Should().Be(1);
    }
}

public sealed class CyFloatComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_less_than()
    {
        using var a = new CyFloat(1.0f);
        using var b = new CyFloat(10.0f);

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyFloat(3.14f);
        using var b = new CyFloat(3.14f);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_greater_than()
    {
        using var a = new CyFloat(100.0f);
        using var b = new CyFloat(1.0f);

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyFloat(42.0f);

        a.CompareTo(null).Should().Be(1);
    }
}

public sealed class CyDoubleComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_less_than()
    {
        using var a = new CyDouble(1.0);
        using var b = new CyDouble(10.0);

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyDouble(3.14159);
        using var b = new CyDouble(3.14159);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_greater_than()
    {
        using var a = new CyDouble(100.0);
        using var b = new CyDouble(1.0);

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyDouble(42.0);

        a.CompareTo(null).Should().Be(1);
    }
}

public sealed class CyDecimalComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_less_than()
    {
        using var a = new CyDecimal(1.0m);
        using var b = new CyDecimal(10.0m);

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyDecimal(99.99m);
        using var b = new CyDecimal(99.99m);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_greater_than()
    {
        using var a = new CyDecimal(100.0m);
        using var b = new CyDecimal(1.0m);

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyDecimal(42.0m);

        a.CompareTo(null).Should().Be(1);
    }
}

public sealed class CyBoolComparableTests
{
    [Fact]
    public void CompareTo_false_is_less_than_true()
    {
        using var a = new CyBool(false);
        using var b = new CyBool(true);

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyBool(true);
        using var b = new CyBool(true);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_true_is_greater_than_false()
    {
        using var a = new CyBool(true);
        using var b = new CyBool(false);

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyBool(true);

        a.CompareTo(null).Should().Be(1);
    }
}

public sealed class CyGuidComparableTests
{
    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        var guid = Guid.NewGuid();
        using var a = new CyGuid(guid);
        using var b = new CyGuid(guid);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_different_guids_returns_nonzero()
    {
        using var a = new CyGuid(Guid.NewGuid());
        using var b = new CyGuid(Guid.NewGuid());

        a.CompareTo(b).Should().NotBe(0);
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyGuid(Guid.NewGuid());

        a.CompareTo(null).Should().Be(1);
    }
}

public sealed class CyStringComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_less_than()
    {
        using var a = new CyString("abc");
        using var b = new CyString("xyz");

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyString("hello");
        using var b = new CyString("hello");

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_greater_than()
    {
        using var a = new CyString("xyz");
        using var b = new CyString("abc");

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyString("test");

        a.CompareTo(null).Should().Be(1);
    }
}

public sealed class CyBytesComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_lexicographically_less()
    {
        using var a = new CyBytes(new byte[] { 1, 2, 3 });
        using var b = new CyBytes(new byte[] { 1, 2, 4 });

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        using var a = new CyBytes(new byte[] { 1, 2, 3 });
        using var b = new CyBytes(new byte[] { 1, 2, 3 });

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_lexicographically_greater()
    {
        using var a = new CyBytes(new byte[] { 1, 2, 4 });
        using var b = new CyBytes(new byte[] { 1, 2, 3 });

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyBytes(new byte[] { 1 });

        a.CompareTo(null).Should().Be(1);
    }

    [Fact]
    public void CompareTo_shorter_array_is_less()
    {
        using var a = new CyBytes(new byte[] { 1, 2 });
        using var b = new CyBytes(new byte[] { 1, 2, 3 });

        a.CompareTo(b).Should().BeNegative();
    }
}

public sealed class CyDateTimeComparableTests
{
    [Fact]
    public void CompareTo_returns_negative_when_earlier()
    {
        using var a = new CyDateTime(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        using var b = new CyDateTime(new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        a.CompareTo(b).Should().BeNegative();
    }

    [Fact]
    public void CompareTo_returns_zero_when_equal()
    {
        var dt = new DateTime(2024, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        using var a = new CyDateTime(dt);
        using var b = new CyDateTime(dt);

        a.CompareTo(b).Should().Be(0);
    }

    [Fact]
    public void CompareTo_returns_positive_when_later()
    {
        using var a = new CyDateTime(new DateTime(2025, 12, 31, 0, 0, 0, DateTimeKind.Utc));
        using var b = new CyDateTime(new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        a.CompareTo(b).Should().BePositive();
    }

    [Fact]
    public void CompareTo_null_returns_1()
    {
        using var a = new CyDateTime(DateTime.UtcNow);

        a.CompareTo(null).Should().Be(1);
    }
}
