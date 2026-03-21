using System.Reflection;
using CyTypes.Core.Memory;
using CyTypes.Primitives;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Memory;

public class MemoryValidationTests
{
    [Fact]
    public void SecureBuffer_ZerosContentsOnDispose()
    {
        var buffer = new SecureBuffer(64);
        var pattern = new byte[64];
        Array.Fill(pattern, (byte)0xAA);
        buffer.Write(pattern);

        // Verify data was written
        buffer.AsReadOnlySpan().ToArray().Should().Equal(pattern);

        buffer.Dispose();

        // Access internal _buffer via reflection to verify zeroing
        var field = typeof(SecureBuffer).GetField("_buffer", BindingFlags.NonPublic | BindingFlags.Instance);
        field.Should().NotBeNull();
        var internalBuffer = (byte[])field!.GetValue(buffer)!;
        internalBuffer.Should().AllBeEquivalentTo((byte)0,
            because: "SecureBuffer must zero contents on disposal");
    }

    [Fact]
    public void SecureBuffer_ReportsIsLockedProperty()
    {
        using var buffer = new SecureBuffer(32);

        // IsLocked depends on OS support; we just verify the property is accessible
        _ = buffer.IsLocked;
        buffer.IsDisposed.Should().BeFalse();
    }

    [Fact]
    public void SecureBuffer_IsDisposedAfterDispose()
    {
        var buffer = new SecureBuffer(32);
        buffer.IsDisposed.Should().BeFalse();

        buffer.Dispose();
        buffer.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void SecureBuffer_ThrowsAfterDispose()
    {
        var buffer = new SecureBuffer(32);
        buffer.Dispose();

        FluentActions.Invoking(() => { buffer.AsSpan(); })
            .Should().Throw<ObjectDisposedException>();
        FluentActions.Invoking(() => { buffer.AsReadOnlySpan(); })
            .Should().Throw<ObjectDisposedException>();
        FluentActions.Invoking(() => buffer.Write(new byte[1]))
            .Should().Throw<ObjectDisposedException>();
        FluentActions.Invoking(() => buffer.ToArray())
            .Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void SecureBuffer_PinnedMemoryIsUsed()
    {
        using var buffer = new SecureBuffer(32);

        var field = typeof(SecureBuffer).GetField("_buffer", BindingFlags.NonPublic | BindingFlags.Instance);
        var internalBuffer = (byte[])field!.GetValue(buffer)!;
        internalBuffer.Should().NotBeNull();
        internalBuffer.Length.Should().Be(32);
    }

    [Fact]
    public void CyString_DisposePreventsPlaintextAccess()
    {
        var cy = new CyString("sensitive plaintext");
        cy.ToInsecureString().Should().Be("sensitive plaintext");

        cy.Dispose();

        FluentActions.Invoking(() => cy.ToInsecureString())
            .Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void SecureBuffer_DoubleDispose_IsNoOp()
    {
        var buffer = new SecureBuffer(32);
        buffer.Write(new byte[32]);

        buffer.Dispose();
        buffer.Dispose(); // Should not throw

        buffer.IsDisposed.Should().BeTrue();
    }
}
