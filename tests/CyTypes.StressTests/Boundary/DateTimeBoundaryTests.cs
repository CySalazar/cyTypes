using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Boundary;

[Trait("Category", "Stress")]
[Trait("SubCategory", "Boundary")]
public class DateTimeBoundaryTests
{
    private readonly ITestOutputHelper _output;
    private readonly SecurityPolicy _policy = SecurityPolicy.Performance;

    public DateTimeBoundaryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void CyDateTime_MinValue()
    {
        using var cyDt = new CyDateTime(DateTime.MinValue, _policy);
        var decrypted = cyDt.ToInsecureDateTime();
        decrypted.Ticks.Should().Be(DateTime.MinValue.Ticks,
            "DateTime.MinValue should round-trip by ticks");
        _output.WriteLine($"DateTime.MinValue round-trip OK (Ticks={decrypted.Ticks})");
    }

    [Fact]
    public void CyDateTime_MaxValue()
    {
        using var cyDt = new CyDateTime(DateTime.MaxValue, _policy);
        var decrypted = cyDt.ToInsecureDateTime();
        decrypted.Ticks.Should().Be(DateTime.MaxValue.Ticks,
            "DateTime.MaxValue should round-trip by ticks");
        _output.WriteLine($"DateTime.MaxValue round-trip OK (Ticks={decrypted.Ticks})");
    }

    [Fact]
    public void CyDateTime_UnixEpoch()
    {
        var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        using var cyDt = new CyDateTime(unixEpoch, _policy);
        var decrypted = cyDt.ToInsecureDateTime();
        decrypted.Ticks.Should().Be(unixEpoch.Ticks,
            "Unix epoch should round-trip by ticks");
        _output.WriteLine($"Unix epoch round-trip OK (Ticks={decrypted.Ticks})");
    }

    [Fact]
    public void CyDateTime_Now()
    {
        var now = DateTime.UtcNow;

        using var cyDt = new CyDateTime(now, _policy);
        var decrypted = cyDt.ToInsecureDateTime();
        decrypted.Ticks.Should().Be(now.Ticks,
            "DateTime.UtcNow should round-trip by ticks");
        _output.WriteLine($"DateTime.UtcNow round-trip OK ({now:O})");
    }
}
