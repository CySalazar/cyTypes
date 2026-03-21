using System.Collections;
using CyTypes.Primitives.Shared;

namespace CyTypes.Collections;

/// <summary>Represents a disposable, strongly-typed list of <see cref="ICyType"/> elements.</summary>
/// <typeparam name="T">The element type, which must implement <see cref="ICyType"/>.</typeparam>
public sealed class CyList<T> : IList<T>, IReadOnlyList<T>, IDisposable where T : ICyType
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

    /// <summary>Gets a value indicating whether the list is read-only. Always returns false.</summary>
    public bool IsReadOnly => false;

    /// <summary>Adds the specified item to the list.</summary>
    public void Add(T item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(item);
        _items.Add(item);
    }

    /// <summary>Adds the elements of the specified collection to the end of the list.</summary>
    public void AddRange(IEnumerable<T> items)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(items);
        foreach (var item in items)
        {
            ArgumentNullException.ThrowIfNull(item);
            _items.Add(item);
        }
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

    /// <summary>
    /// Removes the element at the specified index without disposing it.
    /// Use this when you want to keep a reference to the removed element.
    /// </summary>
    /// <returns>The detached element.</returns>
    public T DetachAt(int index)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        var item = _items[index];
        _items.RemoveAt(index);
        return item;
    }

    /// <summary>
    /// Removes all elements that match the specified predicate. Disposed removed elements.
    /// </summary>
    /// <returns>The number of elements removed.</returns>
    public int RemoveAll(Predicate<T> match)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(match);
        var toRemove = _items.FindAll(match);
        foreach (var item in toRemove)
        {
            _items.Remove(item);
            item.Dispose();
        }
        return toRemove.Count;
    }

    /// <summary>Gets or sets the element at the specified index.</summary>
    /// <remarks>Setting an element disposes the previous value at that index.</remarks>
    public T this[int index]
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _items[index];
        }
        set
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            ArgumentNullException.ThrowIfNull(value);
            var old = _items[index];
            _items[index] = value;
            if (!ReferenceEquals(old, value))
                old.Dispose();
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

    /// <summary>Returns all elements that match the specified predicate as a new CyList (shared references, not clones).</summary>
    public CyList<T> FindAll(Predicate<T> match)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(match);
        var result = new CyList<T>();
        foreach (var item in _items)
        {
            if (match(item))
                result._items.Add(item);
        }
        return result;
    }

    /// <summary>Sorts the list using the specified comparison.</summary>
    public void Sort(Comparison<T> comparison)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(comparison);
        _items.Sort(comparison);
    }

    /// <summary>Performs the specified action on each element of the list.</summary>
    public void ForEach(Action<T> action)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(action);
        _items.ForEach(action);
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
