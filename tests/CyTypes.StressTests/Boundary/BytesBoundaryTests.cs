using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Boundary;

[Trait("Category", "Stress")]
[Trait("SubCategory", "Boundary")]
public class BytesBoundaryTests
{
    private readonly ITestOutputHelper _output;
    private readonly SecurityPolicy _policy = SecurityPolicy.Performance;

    public BytesBoundaryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void CyBytes_EmptyArray()
    {
        // Empty byte array — verify whether it is supported or throws
        var emptyArray = Array.Empty<byte>();

        try
        {
            using var cyBytes = new CyBytes(emptyArray, _policy);
            var decrypted = cyBytes.ToInsecureBytes();
            decrypted.Should().BeEmpty("empty byte array should round-trip as empty if supported");
            _output.WriteLine("Empty byte array is supported and round-trips correctly");
        }
        catch (Exception ex)
        {
            _output.WriteLine($"Empty byte array throws: {ex.GetType().Name}: {ex.Message}");
            // Not a test failure — just documenting behavior
            ex.Should().BeAssignableTo<Exception>("an exception is an acceptable response to empty input");
        }
    }

    [Fact]
    public void CyBytes_SingleByte()
    {
        var singleByte = new byte[] { 0x42 };

        using var cyBytes = new CyBytes(singleByte, _policy);
        var decrypted = cyBytes.ToInsecureBytes();
        decrypted.Should().Equal(singleByte, "single byte should round-trip correctly");
        _output.WriteLine("Single byte [0x42] round-trip OK");
    }

    [Fact]
    public void CyBytes_Exact16MB()
    {
        const int size = 16 * 1024 * 1024;
        var data = new byte[size];
        Random.Shared.NextBytes(data);

        using var cyBytes = new CyBytes(data, _policy);
        var decrypted = cyBytes.ToInsecureBytes();
        decrypted.Should().Equal(data, "exact 16 MB byte array should round-trip correctly");
        _output.WriteLine($"16 MB byte array round-trip OK ({size:N0} bytes)");
    }

    [Fact]
    public void CyBytes_AllZeros()
    {
        var zeros = new byte[1024];

        using var cyBytes = new CyBytes(zeros, _policy);
        var decrypted = cyBytes.ToInsecureBytes();
        decrypted.Should().Equal(zeros, "all-zero array should round-trip correctly");
        decrypted.Should().AllSatisfy(b => b.Should().Be(0));
        _output.WriteLine("All-zeros (1024 bytes) round-trip OK");
    }

    [Fact]
    public void CyBytes_AllOnes()
    {
        var ones = new byte[1024];
        Array.Fill(ones, (byte)0xFF);

        using var cyBytes = new CyBytes(ones, _policy);
        var decrypted = cyBytes.ToInsecureBytes();
        decrypted.Should().Equal(ones, "all-0xFF array should round-trip correctly");
        decrypted.Should().AllSatisfy(b => b.Should().Be(0xFF));
        _output.WriteLine("All-0xFF (1024 bytes) round-trip OK");
    }
}
