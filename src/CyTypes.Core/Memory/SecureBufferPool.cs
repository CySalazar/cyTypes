using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace CyTypes.Core.Memory;

/// <summary>
/// A pool of <see cref="SecureBuffer"/> instances that zeros buffers on return and disposes them on pool disposal.
/// </summary>
public sealed class SecureBufferPool : IDisposable
{
    private readonly int _bufferSize;
    private readonly ConcurrentBag<SecureBuffer> _pool = new();
    private bool _isDisposed;

    /// <summary>Gets the fixed size of each buffer managed by this pool.</summary>
    public int BufferSize => _bufferSize;
    /// <summary>Gets the number of buffers currently available in the pool.</summary>
    public int Count => _pool.Count;

    /// <summary>Initializes a new pool that manages buffers of the specified size.</summary>
    /// <param name="bufferSize">The size in bytes for each buffer. Must be greater than zero.</param>
    public SecureBufferPool(int bufferSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(bufferSize, 0);
        _bufferSize = bufferSize;
    }

    /// <summary>Rents a buffer from the pool, or allocates a new one if the pool is empty.</summary>
    /// <returns>A <see cref="SecureBuffer"/> ready for use.</returns>
    public SecureBuffer Rent()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (_pool.TryTake(out var buffer))
        {
            return buffer;
        }

        return new SecureBuffer(_bufferSize);
    }

    /// <summary>Returns a buffer to the pool after zeroing its contents. Disposed or mismatched buffers are silently ignored.</summary>
    /// <param name="buffer">The buffer to return.</param>
    public void Return(SecureBuffer buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        if (buffer.IsDisposed || buffer.Length != _bufferSize)
            return;

        // Zero on return
        CryptographicOperations.ZeroMemory(buffer.AsSpan());
        _pool.Add(buffer);
    }

    /// <summary>Disposes all pooled buffers and prevents further rentals.</summary>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;

        while (_pool.TryTake(out var buffer))
        {
            buffer.Dispose();
        }
    }
}
