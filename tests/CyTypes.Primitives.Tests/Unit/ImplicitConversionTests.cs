using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class ImplicitConversionTests
{
    [Fact]
    public void CyInt_implicitly_converts_to_CyLong()
    {
        using var cyInt = new CyInt(42);

        CyLong cyLong = cyInt;
        using (cyLong)
        {
            cyLong.ToInsecureLong().Should().Be(42L);
        }
    }

    [Fact]
    public void CyInt_implicitly_converts_to_CyDouble()
    {
        using var cyInt = new CyInt(42);

        CyDouble cyDouble = cyInt;
        using (cyDouble)
        {
            cyDouble.ToInsecureDouble().Should().Be(42.0);
        }
    }

    [Fact]
    public void CyFloat_implicitly_converts_to_CyDouble()
    {
        using var cyFloat = new CyFloat(3.14f);

        CyDouble cyDouble = cyFloat;
        using (cyDouble)
        {
            cyDouble.ToInsecureDouble().Should().BeApproximately(3.14, 0.001);
        }
    }

    [Fact]
    public void CyInt_to_CyLong_preserves_value_for_max_int()
    {
        using var cyInt = new CyInt(int.MaxValue);

        CyLong cyLong = cyInt;
        using (cyLong)
        {
            cyLong.ToInsecureLong().Should().Be((long)int.MaxValue);
        }
    }

    [Fact]
    public void CyInt_to_CyLong_preserves_value_for_min_int()
    {
        using var cyInt = new CyInt(int.MinValue);

        CyLong cyLong = cyInt;
        using (cyLong)
        {
            cyLong.ToInsecureLong().Should().Be((long)int.MinValue);
        }
    }

    [Fact]
    public void CyInt_to_CyDouble_preserves_value_for_negative()
    {
        using var cyInt = new CyInt(-99);

        CyDouble cyDouble = cyInt;
        using (cyDouble)
        {
            cyDouble.ToInsecureDouble().Should().Be(-99.0);
        }
    }

    [Fact]
    public void CyFloat_to_CyDouble_preserves_zero()
    {
        using var cyFloat = new CyFloat(0.0f);

        CyDouble cyDouble = cyFloat;
        using (cyDouble)
        {
            cyDouble.ToInsecureDouble().Should().Be(0.0);
        }
    }
}
