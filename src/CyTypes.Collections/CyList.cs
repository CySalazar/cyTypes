using System.Collections;
using CyTypes.Primitives.Shared;

namespace CyTypes.Collections;

/// <summary>Represents a disposable, strongly-typed list of <see cref="ICyType"/> elements.</summary>
/// <typeparam name="T">The element type, which must implement <see cref="ICyType"/>.</typeparam>
public sealed class CyList<T> : IReadOnlyList<T>, IDisposable where T : ICyType
{
    private readonly List<T> _items = [];
    private bool _isDisposed;

    /// <summary>Gets the number of elements in the list.</summary>
    public int Count
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _items.Count;
        }
    }

    /// <summary>Adds the specified item to the list.</summary>
    public void Add(T item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(item);
        _items.Add(item);
    }

    /// <summary>Inserts an item at the specified index.</summary>
    public void Insert(int index, T item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(item);
        _items.Insert(index, item);
    }

    /// <summary>Removes the first occurrence of the specified item from the list.</summary>
    public bool Remove(T item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.Remove(item);
    }

    /// <summary>Removes and disposes the element at the specified index.</summary>
    public void RemoveAt(int index)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        var item = _items[index];
        _items.RemoveAt(index);
        item.Dispose();
    }

    /// <summary>Gets the element at the specified index.</summary>
    public T this[int index]
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _items[index];
        }
    }

    /// <summary>Returns the zero-based index of the first occurrence of the specified item.</summary>
    public int IndexOf(T item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.IndexOf(item);
    }

    /// <summary>Returns the zero-based index of the last occurrence of the specified item.</summary>
    public int LastIndexOf(T item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.LastIndexOf(item);
    }

    /// <summary>Determines whether the list contains the specified item.</summary>
    public bool Contains(T item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.Contains(item);
    }

    /// <summary>Copies the elements to the specified array.</summary>
    public void CopyTo(T[] array, int arrayIndex)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        _items.CopyTo(array, arrayIndex);
    }

    /// <summary>Disposes and removes all elements from the list.</summary>
    public void Clear()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        foreach (var item in _items)
            item.Dispose();
        _items.Clear();
    }

    /// <summary>Returns an enumerator that iterates through the list.</summary>
    public IEnumerator<T> GetEnumerator()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>Disposes all elements and releases resources used by the list.</summary>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        foreach (var item in _items)
            item.Dispose();
        _items.Clear();
    }
}
