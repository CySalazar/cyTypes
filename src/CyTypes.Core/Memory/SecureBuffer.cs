using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CyTypes.Core.Memory;

/// <summary>
/// A pinned, optionally mlock'd byte buffer that zeros its contents on disposal.
/// Thread-safe: concurrent calls to <see cref="Dispose"/> are safe via atomic CAS.
/// </summary>
public sealed class SecureBuffer : IDisposable
{
    private readonly byte[] _buffer;
    private bool _isLocked;
    private int _isDisposed; // 0 = alive, 1 = disposed (atomic via Interlocked)

    /// <summary>The size of the buffer in bytes.</summary>
    public int Length => _buffer.Length;
    /// <summary>True if OS-level memory locking (mlock/VirtualLock) succeeded.</summary>
    public bool IsLocked => _isLocked;
    /// <summary>True if this buffer has been disposed and its contents zeroed.</summary>
    public bool IsDisposed => Volatile.Read(ref _isDisposed) == 1;

    /// <summary>
    /// Allocates a new pinned secure buffer of the given size and attempts to lock
    /// the underlying memory pages via the OS.
    /// </summary>
    /// <param name="size">Buffer size in bytes. Must be greater than zero.</param>
    public SecureBuffer(int size)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(size, 0);
        _buffer = GC.AllocateArray<byte>(size, pinned: true);
        TryLockMemory();
    }

    /// <summary>Returns a writable span over the buffer contents.</summary>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed.</exception>
    public Span<byte> AsSpan()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        return _buffer.AsSpan();
    }

    /// <summary>Returns a read-only span over the buffer contents.</summary>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed.</exception>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        return _buffer.AsSpan();
    }

    /// <summary>Copies <paramref name="data"/> into the buffer.</summary>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed.</exception>
    /// <exception cref="ArgumentException"><paramref name="data"/> is larger than the buffer.</exception>
    public void Write(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        if (data.Length > _buffer.Length)
            throw new ArgumentException($"Data length {data.Length} exceeds buffer size {_buffer.Length}.");
        data.CopyTo(_buffer);
    }

    /// <summary>Returns a copy of the buffer contents as a new byte array.</summary>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed.</exception>
    public byte[] ToArray()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _isDisposed) == 1, this);
        var copy = new byte[_buffer.Length];
        _buffer.AsSpan().CopyTo(copy);
        return copy;
    }

    /// <summary>
    /// Locks the buffer's memory pages via OS-level mlock/VirtualLock.
    /// The buffer is already pinned (GC.AllocateArray with pinned: true),
    /// so we obtain the address directly without allocating a redundant GCHandle.
    /// </summary>
    private unsafe void TryLockMemory()
    {
        var address = (IntPtr)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(_buffer));
        _isLocked = MemoryLock.TryLock(address, (nuint)_buffer.Length);
    }

    private unsafe void TryUnlockMemory()
    {
        if (!_isLocked) return;

        var address = (IntPtr)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(_buffer));
        MemoryLock.TryUnlock(address, (nuint)_buffer.Length);
        _isLocked = false;
    }

    /// <summary>
    /// Zeros the buffer contents, unlocks memory pages, and marks the buffer as disposed.
    /// Thread-safe: only the first caller performs cleanup; subsequent calls are no-ops.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) != 0)
            return;

        CryptographicOperations.ZeroMemory(_buffer);
        TryUnlockMemory();
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer: zeros buffer contents if not already disposed.</summary>
    ~SecureBuffer()
    {
        if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) == 0)
        {
            CryptographicOperations.ZeroMemory(_buffer);
        }
    }
}
