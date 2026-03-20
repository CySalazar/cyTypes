using CyTypes.Core.Memory;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Memory;

public sealed class SecureBufferThreadSafetyTests
{
    [Fact]
    public async Task ConcurrentDispose_DoesNotThrow()
    {
        var buffer = new SecureBuffer(64);
        buffer.Write(new byte[64]);

        var tasks = Enumerable.Range(0, 100).Select(_ => Task.Run(() =>
        {
            buffer.Dispose();
        })).ToArray();

        await Task.WhenAll(tasks);
        buffer.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task DisposeAndAsSpan_Race_ThrowsOrSucceeds()
    {
        // Run many iterations to exercise the race window
        for (var i = 0; i < 50; i++)
        {
            var buffer = new SecureBuffer(32);
            buffer.Write(new byte[32]);

            var disposeTask = Task.Run(() => buffer.Dispose());
            var spanTask = Task.Run(() =>
            {
                try
                {
                    _ = buffer.AsSpan();
                }
                catch (ObjectDisposedException)
                {
                    // Expected if dispose wins the race
                }
            });

            await Task.WhenAll(disposeTask, spanTask);
            buffer.IsDisposed.Should().BeTrue();
        }
    }

    [Fact]
    public async Task DisposeAndToArray_Race_ThrowsOrSucceeds()
    {
        for (var i = 0; i < 50; i++)
        {
            var buffer = new SecureBuffer(16);
            buffer.Write(new byte[16]);

            var disposeTask = Task.Run(() => buffer.Dispose());
            var toArrayTask = Task.Run(() =>
            {
                try
                {
                    _ = buffer.ToArray();
                }
                catch (ObjectDisposedException)
                {
                    // Expected if dispose wins the race
                }
            });

            await Task.WhenAll(disposeTask, toArrayTask);
            buffer.IsDisposed.Should().BeTrue();
        }
    }
}
