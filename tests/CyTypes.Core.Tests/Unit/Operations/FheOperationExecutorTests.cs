using CyTypes.Core.Operations;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Operations;

public sealed class FheOperationExecutorTests
{
    private readonly FheOperationExecutor _executor = new();

    [Fact]
    public void Add_without_engine_throws_InvalidOperationException()
    {
        var act = () => _executor.Add(new byte[] { 1 }, new byte[] { 2 });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*FHE engine not configured*");
    }

    [Fact]
    public void Multiply_without_engine_throws_InvalidOperationException()
    {
        var act = () => _executor.Multiply(new byte[] { 1 }, new byte[] { 2 });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*FHE engine not configured*");
    }

    [Fact]
    public void Negate_without_engine_throws_InvalidOperationException()
    {
        var act = () => _executor.Negate(new byte[] { 1 });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*FHE engine not configured*");
    }
}
