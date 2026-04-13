using System.Collections.Concurrent;

namespace CyTypes.NativeExport;

/// <summary>
/// Thread-safe table mapping integer handles to managed objects.
/// Allows C callers to hold opaque references to CyType instances
/// without exposing managed pointers across the FFI boundary.
/// </summary>
internal static class HandleTable
{
    private static readonly ConcurrentDictionary<long, object> _handles = new();
    private static long _nextHandle;

    /// <summary>Stores an object and returns a unique handle for it.</summary>
    public static long Allocate(object obj)
    {
        var handle = Interlocked.Increment(ref _nextHandle);
        _handles[handle] = obj;
        return handle;
    }

    /// <summary>Retrieves the object associated with a handle.</summary>
    public static T? Get<T>(long handle) where T : class
    {
        return _handles.TryGetValue(handle, out var obj) ? obj as T : null;
    }

    /// <summary>Removes and disposes the object associated with a handle.</summary>
    public static bool Free(long handle)
    {
        if (_handles.TryRemove(handle, out var obj))
        {
            (obj as IDisposable)?.Dispose();
            return true;
        }
        return false;
    }

    /// <summary>Returns the number of live handles (for diagnostics).</summary>
    public static int Count => _handles.Count;

    /// <summary>Disposes all objects and clears the table.</summary>
    public static void Clear()
    {
        foreach (var kvp in _handles)
        {
            (kvp.Value as IDisposable)?.Dispose();
        }
        _handles.Clear();
    }
}
