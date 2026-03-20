using CyTypes.Core.Security;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace CyTypes.Logging.Tests;

public sealed class LoggingAuditSinkTests
{
    private readonly ILogger _logger = Substitute.For<ILogger>();

    private static SecurityEvent MakeEvent(SecurityEventType type) =>
        new(DateTime.UtcNow, type, Guid.NewGuid(), "test", "Default");

    [Fact]
    public void Receive_logs_Compromised_as_Critical()
    {
        _logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sink = new LoggingAuditSink(_logger);

        sink.Receive(MakeEvent(SecurityEventType.Compromised));

        _logger.Received(1).Log(
            LogLevel.Critical,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    [Fact]
    public void Receive_logs_AutoDestroyed_as_Warning()
    {
        _logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sink = new LoggingAuditSink(_logger);

        sink.Receive(MakeEvent(SecurityEventType.AutoDestroyed));

        _logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    [Fact]
    public void Receive_logs_KeyRotated_as_Information()
    {
        _logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sink = new LoggingAuditSink(_logger);

        sink.Receive(MakeEvent(SecurityEventType.KeyRotated));

        _logger.Received(1).Log(
            LogLevel.Information,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    [Fact]
    public void Receive_logs_Decrypted_as_Debug()
    {
        _logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sink = new LoggingAuditSink(_logger);

        sink.Receive(MakeEvent(SecurityEventType.Decrypted));

        _logger.Received(1).Log(
            LogLevel.Debug,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    [Fact]
    public void Receive_logs_Tainted_as_Warning()
    {
        _logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sink = new LoggingAuditSink(_logger);

        sink.Receive(MakeEvent(SecurityEventType.Tainted));

        _logger.Received(1).Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>());
    }

    [Fact]
    public void Receive_throws_on_null_event()
    {
        var sink = new LoggingAuditSink(_logger);
        var act = () => sink.Receive(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_on_null_logger()
    {
        var act = () => new LoggingAuditSink(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }
}
