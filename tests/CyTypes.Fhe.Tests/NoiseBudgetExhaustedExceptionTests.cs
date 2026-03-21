using CyTypes.Fhe.NoiseBudget;
using FluentAssertions;
using Xunit;

namespace CyTypes.Fhe.Tests;

public sealed class NoiseBudgetExhaustedExceptionTests
{
    [Fact]
    public void Properties_store_values()
    {
        var ex = new NoiseBudgetExhaustedException(5, 10);
        ex.RemainingBits.Should().Be(5);
        ex.MinimumRequired.Should().Be(10);
        ex.Message.Should().Contain("5").And.Contain("10");
    }
}
