using System.Collections;
using System.Diagnostics.CodeAnalysis;
using CyTypes.Primitives.Shared;

namespace CyTypes.Collections;

/// <summary>Represents a disposable dictionary that maps keys to <see cref="ICyType"/> values.</summary>
/// <typeparam name="TKey">The type of keys in the dictionary.</typeparam>
/// <typeparam name="TValue">The type of values, which must implement <see cref="ICyType"/>.</typeparam>
public sealed class CyDictionary<TKey, TValue> : IDictionary<TKey, TValue>, IReadOnlyDictionary<TKey, TValue>, IDisposable
    where TKey : notnull
    where TValue : ICyType
{
    private readonly Dictionary<TKey, TValue> _items = [];
    private bool _isDisposed;

    /// <summary>Gets the number of key-value pairs in the dictionary.</summary>
    public int Count
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _items.Count;
        }
    }

    /// <summary>Gets a value indicating whether the dictionary is read-only. Always returns false.</summary>
    public bool IsReadOnly => false;

    /// <summary>Adds the specified key-value pair to the dictionary.</summary>
    public void Add(TKey key, TValue value)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);
        _items.Add(key, value);
    }

    /// <summary>Adds a key-value pair to the dictionary.</summary>
    void ICollection<KeyValuePair<TKey, TValue>>.Add(KeyValuePair<TKey, TValue> item)
    {
        Add(item.Key, item.Value);
    }

    /// <summary>Removes and disposes the value associated with the specified key.</summary>
    public bool Remove(TKey key)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_items.Remove(key, out var value))
        {
            value.Dispose();
            return true;
        }
        return false;
    }

    /// <summary>Removes the specified key-value pair from the dictionary and disposes the value.</summary>
    bool ICollection<KeyValuePair<TKey, TValue>>.Remove(KeyValuePair<TKey, TValue> item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_items.TryGetValue(item.Key, out var existing) && ReferenceEquals(existing, item.Value))
        {
            _items.Remove(item.Key);
            existing.Dispose();
            return true;
        }
        return false;
    }

    /// <summary>
    /// Removes the value associated with the specified key without disposing it.
    /// Use this when you want to keep a reference to the removed value.
    /// </summary>
    /// <returns>The detached value, or default if the key was not found.</returns>
    public TValue? Detach(TKey key)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_items.Remove(key, out var value))
            return value;
        return default;
    }

    /// <summary>Gets or sets the value associated with the specified key.</summary>
    public TValue this[TKey key]
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _items[key];
        }
        set
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            ArgumentNullException.ThrowIfNull(value);
            if (_items.TryGetValue(key, out var existing))
                existing.Dispose();
            _items[key] = value;
        }
    }

    /// <summary>Determines whether the dictionary contains the specified key.</summary>
    public bool ContainsKey(TKey key)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.ContainsKey(key);
    }

    /// <summary>Determines whether the dictionary contains the specified key-value pair.</summary>
    bool ICollection<KeyValuePair<TKey, TValue>>.Contains(KeyValuePair<TKey, TValue> item)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.TryGetValue(item.Key, out var existing) && ReferenceEquals(existing, item.Value);
    }

    /// <summary>Determines whether the dictionary contains a value equal to the specified value.</summary>
    public bool ContainsValue(TValue value)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.ContainsValue(value);
    }

    /// <summary>Attempts to get the value associated with the specified key.</summary>
    public bool TryGetValue(TKey key, [MaybeNullWhen(false)] out TValue value)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.TryGetValue(key, out value);
    }

    /// <summary>Gets a collection containing the keys in the dictionary.</summary>
    public ICollection<TKey> Keys
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _items.Keys;
        }
    }

    /// <summary>Gets a collection containing the values in the dictionary.</summary>
    public ICollection<TValue> Values
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);
            return _items.Values;
        }
    }

    /// <summary>Gets the keys as an enumerable (IReadOnlyDictionary).</summary>
    IEnumerable<TKey> IReadOnlyDictionary<TKey, TValue>.Keys => Keys;

    /// <summary>Gets the values as an enumerable (IReadOnlyDictionary).</summary>
    IEnumerable<TValue> IReadOnlyDictionary<TKey, TValue>.Values => Values;

    /// <summary>Copies the key-value pairs to the specified array.</summary>
    void ICollection<KeyValuePair<TKey, TValue>>.CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ((ICollection<KeyValuePair<TKey, TValue>>)_items).CopyTo(array, arrayIndex);
    }

    /// <summary>Disposes all values and removes all key-value pairs from the dictionary.</summary>
    public void Clear()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        foreach (var item in _items.Values)
            item.Dispose();
        _items.Clear();
    }

    /// <summary>Returns an enumerator that iterates through the dictionary.</summary>
    public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _items.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>Disposes all values and releases resources used by the dictionary.</summary>
    public void Dispose()
    {
        if (_isDisposed) return;
        _isDisposed = true;
        foreach (var item in _items.Values)
            item.Dispose();
        _items.Clear();
    }
}
