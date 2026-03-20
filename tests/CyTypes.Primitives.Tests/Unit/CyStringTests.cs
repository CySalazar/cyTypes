using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class CyStringTests
{
    [Fact]
    public void Roundtrip_preserves_value()
    {
        using var cy = new CyString("hello");
        cy.ToInsecureString().Should().Be("hello");
    }

    [Fact]
    public void Empty_string_roundtrip()
    {
        using var cy = new CyString("");
        cy.ToInsecureString().Should().BeEmpty();
        cy.Length.Should().Be(0);
        cy.IsEmpty.Should().BeTrue();
    }

    [Fact]
    public void Unicode_roundtrip()
    {
        using var cy = new CyString("こんにちは世界 🌍");
        cy.ToInsecureString().Should().Be("こんにちは世界 🌍");
    }

    [Fact]
    public void Length_does_not_decrypt()
    {
        using var cy = new CyString("test");
        cy.Length.Should().Be(4);
        cy.IsCompromised.Should().BeFalse();
    }

    [Fact]
    public void ToInsecureString_marks_compromised()
    {
        using var cy = new CyString("secret");
        cy.IsCompromised.Should().BeFalse();
        _ = cy.ToInsecureString();
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void ToString_never_leaks_plaintext()
    {
        using var cy = new CyString("secret");
        cy.ToString().Should().Contain("Encrypted").And.NotContain("secret");
    }

    [Fact]
    public void Implicit_conversion_from_string()
    {
        CyString cy = "hello";
        using (cy)
        {
            cy.ToInsecureString().Should().Be("hello");
            cy.Policy.Should().BeSameAs(SecurityPolicy.Balanced);
        }
    }

    [Fact]
    public void Explicit_conversion_to_string_marks_compromised()
    {
        using var cy = new CyString("test");
        string raw = (string)cy;
        raw.Should().Be("test");
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void IsNullOrEmpty_null() => CyString.IsNullOrEmpty(null).Should().BeTrue();

    [Fact]
    public void IsNullOrEmpty_empty()
    {
        using var cy = new CyString("");
        CyString.IsNullOrEmpty(cy).Should().BeTrue();
    }

    [Fact]
    public void IsNullOrEmpty_nonEmpty()
    {
        using var cy = new CyString("x");
        CyString.IsNullOrEmpty(cy).Should().BeFalse();
    }

    [Fact]
    public void IsNullOrWhiteSpace_null() => CyString.IsNullOrWhiteSpace(null).Should().BeTrue();

    [Fact]
    public void IsNullOrWhiteSpace_whitespace()
    {
        using var cy = new CyString("   ");
        CyString.IsNullOrWhiteSpace(cy).Should().BeTrue();
    }

    [Fact]
    public void IsNullOrWhiteSpace_nonWhitespace()
    {
        using var cy = new CyString("x");
        CyString.IsNullOrWhiteSpace(cy).Should().BeFalse();
    }
}

public sealed class CyStringOperatorTests
{
    [Fact]
    public void Concatenation_operator()
    {
        using var a = new CyString("hello ");
        using var b = new CyString("world");
        using var c = a + b;
        c.ToInsecureString().Should().Be("hello world");
    }

    [Fact]
    public void Equality_same_value()
    {
        using var a = new CyString("test");
        using var b = new CyString("test");
        (a == b).Should().BeTrue();
        (a != b).Should().BeFalse();
    }

    [Fact]
    public void Equality_different_values()
    {
        using var a = new CyString("abc");
        using var b = new CyString("def");
        (a == b).Should().BeFalse();
        (a != b).Should().BeTrue();
    }

    [Fact]
    public void Null_equality()
    {
        using var a = new CyString("x");
        (a == null).Should().BeFalse();
        (null == a).Should().BeFalse();
        ((CyString?)null == null).Should().BeTrue();
    }

    [Fact]
    public void Indexer_marks_compromised()
    {
        using var cy = new CyString("abc");
        var ch = cy[1];
        ch.Should().Be('b');
        cy.IsCompromised.Should().BeTrue();
    }

    [Fact]
    public void Taint_propagates_through_concatenation()
    {
        using var a = new CyString("a"); a.MarkTainted();
        using var b = new CyString("b");
        using var c = a + b;
        c.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Equality_constant_time_same_length_different_content()
    {
        using var a = new CyString("abcdef");
        using var b = new CyString("abcdeg");
        (a == b).Should().BeFalse();
    }

    [Fact]
    public void Equality_different_length_strings()
    {
        using var a = new CyString("short");
        using var b = new CyString("muchlongerstring");
        (a == b).Should().BeFalse();
        (b == a).Should().BeFalse();
    }
}

public sealed class CyStringMethodTests
{
    [Fact]
    public void Substring_from_index()
    {
        using var cy = new CyString("hello world");
        using var sub = cy.Substring(6);
        sub.ToInsecureString().Should().Be("world");
    }

    [Fact]
    public void Substring_with_length()
    {
        using var cy = new CyString("hello world");
        using var sub = cy.Substring(0, 5);
        sub.ToInsecureString().Should().Be("hello");
    }

    [Fact]
    public void Trim() { using var cy = new CyString("  hello  "); using var t = cy.Trim(); t.ToInsecureString().Should().Be("hello"); }
    [Fact]
    public void TrimStart() { using var cy = new CyString("  hello"); using var t = cy.TrimStart(); t.ToInsecureString().Should().Be("hello"); }
    [Fact]
    public void TrimEnd() { using var cy = new CyString("hello  "); using var t = cy.TrimEnd(); t.ToInsecureString().Should().Be("hello"); }
    [Fact]
    public void ToUpper() { using var cy = new CyString("hello"); using var t = cy.ToUpper(); t.ToInsecureString().Should().Be("HELLO"); }
    [Fact]
    public void ToLower() { using var cy = new CyString("HELLO"); using var t = cy.ToLower(); t.ToInsecureString().Should().Be("hello"); }

    [Fact]
    public void Replace()
    {
        using var cy = new CyString("hello world");
        using var r = cy.Replace("world", "earth");
        r.ToInsecureString().Should().Be("hello earth");
    }

    [Fact]
    public void Contains() { using var cy = new CyString("hello world"); cy.Contains("world").Should().BeTrue(); cy.Contains("xyz").Should().BeFalse(); }
    [Fact]
    public void StartsWith() { using var cy = new CyString("hello"); cy.StartsWith("hel").Should().BeTrue(); cy.StartsWith("xyz").Should().BeFalse(); }
    [Fact]
    public void EndsWith() { using var cy = new CyString("hello"); cy.EndsWith("llo").Should().BeTrue(); cy.EndsWith("xyz").Should().BeFalse(); }
    [Fact]
    public void IndexOf() { using var cy = new CyString("hello"); cy.IndexOf("ll").Should().Be(2); cy.IndexOf("xyz").Should().Be(-1); }
    [Fact]
    public void LastIndexOf() { using var cy = new CyString("abcabc"); cy.LastIndexOf("abc").Should().Be(3); }

    [Fact]
    public void Split()
    {
        using var cy = new CyString("a,b,c");
        var parts = cy.Split(',');
        parts.Should().HaveCount(3);
        parts[0].ToInsecureString().Should().Be("a");
        parts[1].ToInsecureString().Should().Be("b");
        parts[2].ToInsecureString().Should().Be("c");
        foreach (var p in parts) p.Dispose();
    }

    [Fact]
    public void Insert()
    {
        using var cy = new CyString("helloworld");
        using var r = cy.Insert(5, " ");
        r.ToInsecureString().Should().Be("hello world");
    }

    [Fact]
    public void Remove()
    {
        using var cy = new CyString("hello world");
        using var r = cy.Remove(5);
        r.ToInsecureString().Should().Be("hello");
    }

    [Fact]
    public void PadLeft()
    {
        using var cy = new CyString("hi");
        using var r = cy.PadLeft(5);
        r.ToInsecureString().Should().Be("   hi");
    }

    [Fact]
    public void PadRight()
    {
        using var cy = new CyString("hi");
        using var r = cy.PadRight(5);
        r.ToInsecureString().Should().Be("hi   ");
    }

    [Fact]
    public void Static_Concat()
    {
        using var a = new CyString("hello ");
        using var b = new CyString("world");
        using var c = CyString.Concat(a, b);
        c.ToInsecureString().Should().Be("hello world");
    }

    [Fact]
    public void Static_Join()
    {
        using var a = new CyString("a");
        using var b = new CyString("b");
        using var c = new CyString("c");
        using var result = CyString.Join(", ", a, b, c);
        result.ToInsecureString().Should().Be("a, b, c");
    }

    [Fact]
    public void SecureEquals_same_value()
    {
        using var a = new CyString("secret");
        using var b = new CyString("secret");
        a.SecureEquals(b).Should().BeTrue();
    }

    [Fact]
    public void SecureEquals_different_values()
    {
        using var a = new CyString("secret");
        using var b = new CyString("other");
        a.SecureEquals(b).Should().BeFalse();
    }

    [Fact]
    public void SecureContains() { using var cy = new CyString("hello world"); cy.SecureContains("world").Should().BeTrue(); }
    [Fact]
    public void SecureStartsWith() { using var cy = new CyString("hello"); cy.SecureStartsWith("hel").Should().BeTrue(); }
    [Fact]
    public void SecureEndsWith() { using var cy = new CyString("hello"); cy.SecureEndsWith("llo").Should().BeTrue(); }

    [Fact]
    public void EnclaveOp_propagates_taint()
    {
        using var cy = new CyString("hello"); cy.MarkTainted();
        using var upper = cy.ToUpper();
        upper.IsTainted.Should().BeTrue();
    }

    [Fact]
    public void Split_propagates_taint_from_tainted_source()
    {
        using var cy = new CyString("a,b,c"); cy.MarkTainted();
        var parts = cy.Split(',');
        parts.Should().AllSatisfy(p => p.IsTainted.Should().BeTrue());
        foreach (var p in parts) p.Dispose();
    }

    [Fact]
    public void Split_propagates_taint_from_compromised_source()
    {
        using var cy = new CyString("a,b,c"); cy.MarkCompromised();
        var parts = cy.Split(',');
        parts.Should().AllSatisfy(p => p.IsTainted.Should().BeTrue());
        foreach (var p in parts) p.Dispose();
    }

    private static readonly char[] CommaSemicolonSeparators = [',', ';'];

    [Fact]
    public void Split_char_array_propagates_taint()
    {
        using var cy = new CyString("a;b,c"); cy.MarkTainted();
        var parts = cy.Split(CommaSemicolonSeparators);
        parts.Should().HaveCount(3);
        parts.Should().AllSatisfy(p => p.IsTainted.Should().BeTrue());
        foreach (var p in parts) p.Dispose();
    }

    [Fact]
    public void Split_clean_source_produces_clean_results()
    {
        using var cy = new CyString("a,b,c");
        var parts = cy.Split(',');
        parts.Should().AllSatisfy(p => p.IsTainted.Should().BeFalse());
        foreach (var p in parts) p.Dispose();
    }
}

public sealed class CyStringSizeValidationTests
{
    [Fact]
    public void Constructor_accepts_normal_string()
    {
        using var cy = new CyString("hello");
        cy.Length.Should().Be(5);
    }

    [Fact]
    public void Constructor_accepts_empty_string()
    {
        using var cy = new CyString("");
        cy.Length.Should().Be(0);
    }
}

public sealed class CyBytesSizeValidationTests
{
    [Fact]
    public void Constructor_accepts_normal_bytes()
    {
        using var cy = new CyBytes(new byte[] { 1, 2, 3 });
        cy.Length.Should().Be(3);
    }

    [Fact]
    public void Constructor_accepts_empty_bytes()
    {
        using var cy = new CyBytes(Array.Empty<byte>());
        cy.Length.Should().Be(0);
    }
}
