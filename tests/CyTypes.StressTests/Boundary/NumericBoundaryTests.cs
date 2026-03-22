using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Boundary;

[Trait("Category", "Stress")]
[Trait("SubCategory", "Boundary")]
public class NumericBoundaryTests
{
    private readonly ITestOutputHelper _output;
    private readonly SecurityPolicy _policy = SecurityPolicy.Performance;

    public NumericBoundaryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Theory]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1)]
    public void CyInt_BoundaryValues_RoundTrip(int value)
    {
        using var cyInt = new CyInt(value, _policy);
        var decrypted = cyInt.ToInsecureInt();
        decrypted.Should().Be(value);
        _output.WriteLine($"CyInt({value}) round-trip OK");
    }

    [Theory]
    [InlineData(long.MinValue)]
    [InlineData(long.MaxValue)]
    [InlineData(0L)]
    public void CyLong_BoundaryValues_RoundTrip(long value)
    {
        using var cyLong = new CyLong(value, _policy);
        var decrypted = cyLong.ToInsecureLong();
        decrypted.Should().Be(value);
        _output.WriteLine($"CyLong({value}) round-trip OK");
    }

    [Fact]
    public void CyDecimal_BoundaryValues_RoundTrip()
    {
        var values = new[]
        {
            decimal.MinValue,
            decimal.MaxValue,
            decimal.Zero,
            decimal.One,
            decimal.MinusOne
        };

        foreach (var value in values)
        {
            using var cyDecimal = new CyDecimal(value, _policy);
            var decrypted = cyDecimal.ToInsecureDecimal();
            decrypted.Should().Be(value);
            _output.WriteLine($"CyDecimal({value}) round-trip OK");
        }
    }

    [Fact]
    public void CyDouble_SpecialValues_RoundTrip()
    {
        // NaN
        using (var cyNaN = new CyDouble(double.NaN, _policy))
        {
            var decrypted = cyNaN.ToInsecureDouble();
            double.IsNaN(decrypted).Should().BeTrue("NaN should round-trip as NaN");
            _output.WriteLine("CyDouble(NaN) round-trip OK");
        }

        // PositiveInfinity
        using (var cyPosInf = new CyDouble(double.PositiveInfinity, _policy))
        {
            cyPosInf.ToInsecureDouble().Should().Be(double.PositiveInfinity);
            _output.WriteLine("CyDouble(+Inf) round-trip OK");
        }

        // NegativeInfinity
        using (var cyNegInf = new CyDouble(double.NegativeInfinity, _policy))
        {
            cyNegInf.ToInsecureDouble().Should().Be(double.NegativeInfinity);
            _output.WriteLine("CyDouble(-Inf) round-trip OK");
        }

        // Epsilon
        using (var cyEpsilon = new CyDouble(double.Epsilon, _policy))
        {
            cyEpsilon.ToInsecureDouble().Should().Be(double.Epsilon);
            _output.WriteLine("CyDouble(Epsilon) round-trip OK");
        }

        // MinValue
        using (var cyMin = new CyDouble(double.MinValue, _policy))
        {
            cyMin.ToInsecureDouble().Should().Be(double.MinValue);
            _output.WriteLine("CyDouble(MinValue) round-trip OK");
        }

        // MaxValue
        using (var cyMax = new CyDouble(double.MaxValue, _policy))
        {
            cyMax.ToInsecureDouble().Should().Be(double.MaxValue);
            _output.WriteLine("CyDouble(MaxValue) round-trip OK");
        }
    }

    [Fact]
    public void CyFloat_SpecialValues_RoundTrip()
    {
        // NaN
        using (var cyNaN = new CyFloat(float.NaN, _policy))
        {
            var decrypted = cyNaN.ToInsecureFloat();
            float.IsNaN(decrypted).Should().BeTrue("NaN should round-trip as NaN");
            _output.WriteLine("CyFloat(NaN) round-trip OK");
        }

        // PositiveInfinity
        using (var cyPosInf = new CyFloat(float.PositiveInfinity, _policy))
        {
            cyPosInf.ToInsecureFloat().Should().Be(float.PositiveInfinity);
            _output.WriteLine("CyFloat(+Inf) round-trip OK");
        }

        // NegativeInfinity
        using (var cyNegInf = new CyFloat(float.NegativeInfinity, _policy))
        {
            cyNegInf.ToInsecureFloat().Should().Be(float.NegativeInfinity);
            _output.WriteLine("CyFloat(-Inf) round-trip OK");
        }

        // Epsilon
        using (var cyEpsilon = new CyFloat(float.Epsilon, _policy))
        {
            cyEpsilon.ToInsecureFloat().Should().Be(float.Epsilon);
            _output.WriteLine("CyFloat(Epsilon) round-trip OK");
        }

        // MinValue
        using (var cyMin = new CyFloat(float.MinValue, _policy))
        {
            cyMin.ToInsecureFloat().Should().Be(float.MinValue);
            _output.WriteLine("CyFloat(MinValue) round-trip OK");
        }

        // MaxValue
        using (var cyMax = new CyFloat(float.MaxValue, _policy))
        {
            cyMax.ToInsecureFloat().Should().Be(float.MaxValue);
            _output.WriteLine("CyFloat(MaxValue) round-trip OK");
        }
    }

    [Fact]
    public void CyBool_TrueAndFalse_RoundTrip()
    {
        using var cyTrue = new CyBool(true, _policy);
        cyTrue.ToInsecureBool().Should().BeTrue();

        using var cyFalse = new CyBool(false, _policy);
        cyFalse.ToInsecureBool().Should().BeFalse();

        _output.WriteLine("CyBool true/false round-trip OK");
    }

    [Fact]
    public void CyGuid_EmptyAndRandom_RoundTrip()
    {
        using var cyEmpty = new CyGuid(Guid.Empty, _policy);
        cyEmpty.ToInsecureGuid().Should().Be(Guid.Empty);

        var randomGuid = Guid.NewGuid();
        using var cyRandom = new CyGuid(randomGuid, _policy);
        cyRandom.ToInsecureGuid().Should().Be(randomGuid);

        _output.WriteLine("CyGuid Empty and NewGuid round-trip OK");
    }
}
