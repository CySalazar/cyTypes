using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Boundary;

[Trait("Category", "Stress")]
[Trait("SubCategory", "Boundary")]
public class StringBoundaryTests
{
    private readonly ITestOutputHelper _output;
    private readonly SecurityPolicy _policy = SecurityPolicy.Performance;

    public StringBoundaryTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void CyString_Empty()
    {
        using var cyString = new CyString(string.Empty, _policy);
        var decrypted = cyString.ToInsecureString();
        decrypted.Should().BeEmpty("empty string should round-trip as empty");
        _output.WriteLine("Empty string round-trip OK");
    }

    [Fact]
    public void CyString_SingleChar()
    {
        using var cyString = new CyString("A", _policy);
        var decrypted = cyString.ToInsecureString();
        decrypted.Should().Be("A");
        _output.WriteLine("Single char 'A' round-trip OK");
    }

    [Fact]
    public void CyString_LargeString_100K()
    {
        var largeString = new string('X', 100_000);

        using var cyString = new CyString(largeString, _policy);
        var decrypted = cyString.ToInsecureString();
        decrypted.Should().Be(largeString, "100K character string should round-trip correctly");
        _output.WriteLine($"100K string round-trip OK (length={decrypted.Length})");
    }

    [Fact]
    public void CyString_Unicode_Multibyte()
    {
        // Emoji + CJK + Arabic characters
        const string unicodeString = "\U0001F600\U0001F680 \u4e16\u754c \u0645\u0631\u062d\u0628\u0627";

        using var cyString = new CyString(unicodeString, _policy);
        var decrypted = cyString.ToInsecureString();
        decrypted.Should().Be(unicodeString, "multibyte Unicode characters should round-trip correctly");
        _output.WriteLine($"Unicode multibyte round-trip OK: \"{decrypted}\"");
    }

    [Fact]
    public void CyString_NullTerminators()
    {
        var stringWithNulls = "hello\0world\0end";

        using var cyString = new CyString(stringWithNulls, _policy);
        var decrypted = cyString.ToInsecureString();
        decrypted.Should().Be(stringWithNulls, "embedded null terminators should be preserved");
        decrypted.Length.Should().Be(stringWithNulls.Length);
        _output.WriteLine($"Null terminator string round-trip OK (length={decrypted.Length})");
    }
}
