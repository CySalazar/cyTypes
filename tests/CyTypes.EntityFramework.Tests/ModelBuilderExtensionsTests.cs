using CyTypes.EntityFramework;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace CyTypes.EntityFramework.Tests;

public sealed class ModelBuilderExtensionsTests
{
    [Fact]
    public void UseCyTypes_throws_on_null_configurationBuilder()
    {
        ModelConfigurationBuilder builder = null!;
        var act = () => builder.UseCyTypes();
        act.Should().Throw<ArgumentNullException>();
    }
}
