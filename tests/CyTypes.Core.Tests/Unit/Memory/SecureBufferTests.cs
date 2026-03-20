using CyTypes.Core.Memory;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Memory;

public sealed class SecureBufferTests
{
    [Fact]
    public void Constructor_AllocatesBufferOfGivenSize()
    {
        using var buffer = new SecureBuffer(64);
        buffer.Length.Should().Be(64);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Constructor_ThrowsForSizeLessThanOrEqualToZero(int size)
    {
        var act = () => new SecureBuffer(size);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Length_ReturnsCorrectValue()
    {
        using var buffer = new SecureBuffer(128);
        buffer.Length.Should().Be(128);
    }

    [Fact]
    public void AsSpan_CanReadAndWriteViaSpan()
    {
        using var buffer = new SecureBuffer(4);
        var span = buffer.AsSpan();
        span[0] = 0xCA;
        span[1] = 0xFE;
        span[2] = 0xBA;
        span[3] = 0xBE;

        buffer.AsReadOnlySpan().ToArray().Should().Equal(0xCA, 0xFE, 0xBA, 0xBE);
    }

    [Fact]
    public void Write_CopiesDataCorrectly()
    {
        using var buffer = new SecureBuffer(8);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };
        buffer.Write(data);
        buffer.AsReadOnlySpan().ToArray().Should().Equal(data);
    }

    [Fact]
    public void Write_ThrowsIfDataExceedsBufferSize()
    {
        using var buffer = new SecureBuffer(4);
        byte[] oversized = { 1, 2, 3, 4, 5 };
        var act = () => buffer.Write(oversized);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ToArray_ReturnsCopyOfContents()
    {
        using var buffer = new SecureBuffer(3);
        buffer.Write(new byte[] { 10, 20, 30 });
        var copy = buffer.ToArray();
        copy.Should().Equal(10, 20, 30);

        copy[0] = 0xFF;
        buffer.AsReadOnlySpan()[0].Should().Be(10);
    }

    [Fact]
    public void AsSpan_ThrowsObjectDisposedException_AfterDispose()
    {
        var buffer = new SecureBuffer(16);
        buffer.Dispose();

        // Span-returning methods can't be wrapped in Action, use Assert.Throws
        Assert.Throws<ObjectDisposedException>(() => { _ = buffer.AsSpan(); });
    }

    [Fact]
    public void AsReadOnlySpan_ThrowsObjectDisposedException_AfterDispose()
    {
        var buffer = new SecureBuffer(16);
        buffer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { _ = buffer.AsReadOnlySpan(); });
    }

    [Fact]
    public void Dispose_ZerosTheMemory()
    {
        var buffer = new SecureBuffer(8);
        buffer.Write(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

        buffer.IsDisposed.Should().BeFalse();
        buffer.Dispose();
        buffer.IsDisposed.Should().BeTrue();

        Assert.Throws<ObjectDisposedException>(() => { _ = buffer.AsSpan(); });
    }

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var buffer = new SecureBuffer(32);
        var act = () =>
        {
            buffer.Dispose();
            buffer.Dispose();
        };
        act.Should().NotThrow();
    }
}
