using CyTypes.Core.Policy;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace CyTypes.StressTests.Resilience;

[Trait("Category", "Stress"), Trait("SubCategory", "Resilience")]
public class PolicyViolationTests
{
    private readonly ITestOutputHelper _output;

    public PolicyViolationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void FheOperation_WithoutEngine_ThrowsGracefully()
    {
        // Since no FHE engine is registered (static engine provider),
        // creating a CyInt with HomomorphicBasic policy should throw
        // InvalidOperationException at construction time.
        var act = () => new CyInt(10, SecurityPolicy.HomomorphicBasic);

        act.Should().Throw<InvalidOperationException>(
            "creating a HomomorphicBasic CyInt without registered FHE engine should throw");

        _output.WriteLine("FHE operation without engine correctly threw InvalidOperationException");
    }
}
