using FluentAssertions;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace CyTypes.Logging.Tests;

public sealed class CyTypesLoggingExtensionsTests
{
    [Fact]
    public void AddCyTypesRedaction_throws_on_null_factory()
    {
        ILoggerFactory factory = null!;
        var act = () => factory.AddCyTypesRedaction(Substitute.For<ILoggerProvider>());
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddCyTypesRedaction_throws_on_null_provider()
    {
        using var factory = new LoggerFactory();
        var act = () => factory.AddCyTypesRedaction(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddCyTypesRedaction_returns_same_factory()
    {
        using var factory = new LoggerFactory();
        var inner = Substitute.For<ILoggerProvider>();
        inner.CreateLogger(Arg.Any<string>()).Returns(Substitute.For<ILogger>());

        var result = factory.AddCyTypesRedaction(inner);
        result.Should().BeSameAs(factory);
    }
}
