using CyTypes.Core.Memory;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Memory;

public sealed class SecureBufferPoolTests
{
    [Fact]
    public void Rent_ReturnsBufferOfCorrectSize()
    {
        using var pool = new SecureBufferPool(64);

        using var buffer = pool.Rent();

        buffer.Length.Should().Be(64);
    }

    [Fact]
    public void ReturnAndReRent_ReturnsABuffer()
    {
        using var pool = new SecureBufferPool(32);

        var buffer = pool.Rent();
        pool.Return(buffer);

        using var reRented = pool.Rent();

        reRented.Should().NotBeNull();
        reRented.Length.Should().Be(32);
    }

    [Fact]
    public void Count_IncreasesAfterReturn()
    {
        using var pool = new SecureBufferPool(16);

        pool.Count.Should().Be(0);

        var buffer = pool.Rent();
        pool.Return(buffer);

        pool.Count.Should().Be(1);
    }

    [Fact]
    public void Dispose_DisposesAllPooledBuffers()
    {
        var pool = new SecureBufferPool(16);

        var buffer1 = pool.Rent();
        var buffer2 = pool.Rent();
        pool.Return(buffer1);
        pool.Return(buffer2);

        pool.Dispose();

        buffer1.IsDisposed.Should().BeTrue();
        buffer2.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void Return_IgnoresDisposedBuffers()
    {
        using var pool = new SecureBufferPool(16);

        var buffer = pool.Rent();
        buffer.Dispose();

        // Should not add a disposed buffer back to the pool
        pool.Return(buffer);

        pool.Count.Should().Be(0);
    }

    [Fact]
    public void Return_IgnoresWrongSizedBuffers()
    {
        using var pool = new SecureBufferPool(32);

        using var wrongSize = new SecureBuffer(64);

        pool.Return(wrongSize);

        pool.Count.Should().Be(0);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-50)]
    public void Constructor_ThrowsForSizeLessThanOrEqualToZero(int size)
    {
        var act = () => new SecureBufferPool(size);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}
