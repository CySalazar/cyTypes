using FluentAssertions;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace CyTypes.Logging.Tests;

public sealed class RedactingLoggerTests
{
    [Fact]
    public void RedactCyTypes_returns_null_unchanged()
    {
        RedactingLogger.RedactCyTypes(null!).Should().BeNull();
    }

    [Fact]
    public void RedactCyTypes_returns_empty_unchanged()
    {
        RedactingLogger.RedactCyTypes("").Should().BeEmpty();
    }

    [Fact]
    public void RedactCyTypes_redacts_CyType_metadata_pattern()
    {
        var input = "Value is [CyInt:Encrypted|Policy=Balanced|Compromised=False] here";
        var result = RedactingLogger.RedactCyTypes(input);
        result.Should().NotContain("[CyInt:Encrypted");
        result.Should().Contain("[REDACTED:CyType]");
    }

    [Fact]
    public void RedactCyTypes_redacts_hex_payload_64_chars()
    {
        var hex = new string('a', 64);
        var input = $"Payload: {hex} end";
        var result = RedactingLogger.RedactCyTypes(input);
        result.Should().NotContain(hex);
        result.Should().Contain("[REDACTED:CyType]");
    }

    [Fact]
    public void RedactCyTypes_does_not_redact_short_hex_below_64_chars()
    {
        var hex = new string('a', 32);
        var input = $"Short hex: {hex} end";
        var result = RedactingLogger.RedactCyTypes(input);
        result.Should().Contain(hex);
    }

    [Fact]
    public void RedactCyTypes_redacts_base64_payload_48_chars()
    {
        var base64 = new string('A', 48);
        var input = $"Data: {base64} end";
        var result = RedactingLogger.RedactCyTypes(input);
        result.Should().NotContain(base64);
        result.Should().Contain("[REDACTED:CyType]");
    }

    [Fact]
    public void RedactCyTypes_does_not_redact_short_base64_below_48_chars()
    {
        var base64 = new string('A', 30);
        var input = $"Short: {base64} end";
        var result = RedactingLogger.RedactCyTypes(input);
        result.Should().Contain(base64);
    }

    [Fact]
    public void RedactCyTypes_handles_multiple_patterns_in_one_message()
    {
        var hex = new string('b', 64);
        var input = $"[CyInt:Encrypted|Policy=Default|Compromised=False] and {hex}";
        var result = RedactingLogger.RedactCyTypes(input);
        result.Should().NotContain("[CyInt:Encrypted");
        result.Should().NotContain(hex);
    }

    [Fact]
    public void RedactCyTypes_preserves_normal_text()
    {
        var input = "Hello, this is a normal log message with no secrets.";
        var result = RedactingLogger.RedactCyTypes(input);
        result.Should().Be(input);
    }

    [Fact]
    public void Log_delegates_to_inner_with_redacted_message()
    {
        var inner = Substitute.For<ILogger>();
        inner.IsEnabled(Arg.Any<LogLevel>()).Returns(true);

        var logger = new RedactingLogger(inner);
        var hex = new string('c', 64);

        logger.Log(LogLevel.Information, 0, hex, null, (s, _) => s);

        inner.Received(1).Log(
            LogLevel.Information,
            Arg.Any<EventId>(),
            Arg.Any<string>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<string, Exception?, string>>());
    }

    [Fact]
    public void Log_skips_when_not_enabled()
    {
        var inner = Substitute.For<ILogger>();
        inner.IsEnabled(Arg.Any<LogLevel>()).Returns(false);

        var logger = new RedactingLogger(inner);
        logger.Log(LogLevel.Debug, 0, "test", null, (s, _) => s);

        inner.DidNotReceive().Log(
            Arg.Any<LogLevel>(),
            Arg.Any<EventId>(),
            Arg.Any<string>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<string, Exception?, string>>());
    }

    [Fact]
    public void IsEnabled_delegates_to_inner()
    {
        var inner = Substitute.For<ILogger>();
        inner.IsEnabled(LogLevel.Warning).Returns(true);
        inner.IsEnabled(LogLevel.Trace).Returns(false);

        var logger = new RedactingLogger(inner);

        logger.IsEnabled(LogLevel.Warning).Should().BeTrue();
        logger.IsEnabled(LogLevel.Trace).Should().BeFalse();
    }

    [Fact]
    public void BeginScope_delegates_to_inner()
    {
        var inner = Substitute.For<ILogger>();
        var expectedScope = Substitute.For<IDisposable>();
        inner.BeginScope("scope").Returns(expectedScope);

        var logger = new RedactingLogger(inner);
        var scope = logger.BeginScope("scope");

        scope.Should().BeSameAs(expectedScope);
    }

    [Fact]
    public void Constructor_throws_on_null_inner()
    {
        var act = () => new RedactingLogger(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("inner");
    }
}
