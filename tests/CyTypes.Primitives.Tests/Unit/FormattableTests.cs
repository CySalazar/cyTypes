using System.Globalization;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Primitives.Tests.Unit;

public sealed class FormattableTests
{
    [Fact]
    public void CyInt_ToString_with_format_and_provider_returns_redacted_string()
    {
        using var cy = new CyInt(42);

        var formatted = ((IFormattable)cy).ToString("N0", CultureInfo.InvariantCulture);

        formatted.Should().Be(cy.ToString());
        formatted.Should().NotContain("42");
    }

    [Fact]
    public void CyString_ToString_with_format_and_provider_returns_redacted_string()
    {
        using var cy = new CyString("secret");

        var formatted = ((IFormattable)cy).ToString("G", CultureInfo.InvariantCulture);

        formatted.Should().Be(cy.ToString());
        formatted.Should().NotContain("secret");
    }

    [Fact]
    public void CyDouble_ToString_with_format_and_provider_returns_redacted_string()
    {
        using var cy = new CyDouble(3.14159);

        var formatted = ((IFormattable)cy).ToString("F2", CultureInfo.InvariantCulture);

        formatted.Should().Be(cy.ToString());
        formatted.Should().NotContain("3.14");
    }

    [Fact]
    public void CyBool_ToString_with_format_and_provider_returns_redacted_string()
    {
        using var cy = new CyBool(true);

        var formatted = ((IFormattable)cy).ToString(null, CultureInfo.InvariantCulture);

        formatted.Should().Be(cy.ToString());
        formatted.Should().NotContain("True");
        formatted.Should().NotContain("true");
    }

    [Fact]
    public void CyDateTime_ToString_with_format_and_provider_never_contains_plaintext()
    {
        var dt = new DateTime(2024, 6, 15, 12, 30, 0, DateTimeKind.Utc);
        using var cy = new CyDateTime(dt);

        var formatted = ((IFormattable)cy).ToString("O", CultureInfo.InvariantCulture);

        formatted.Should().Be(cy.ToString());
        formatted.Should().Contain("Encrypted");
        formatted.Should().NotContain("2024");
    }

    [Fact]
    public void CyDecimal_ToString_with_format_and_provider_returns_redacted_string()
    {
        using var cy = new CyDecimal(99.99m);

        var formatted = ((IFormattable)cy).ToString("C", CultureInfo.InvariantCulture);

        formatted.Should().Be(cy.ToString());
        formatted.Should().NotContain("99.99");
    }
}
