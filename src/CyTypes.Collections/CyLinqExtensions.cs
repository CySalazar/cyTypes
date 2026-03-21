using CyTypes.Primitives.Shared;

namespace CyTypes.Collections;

/// <summary>LINQ extension methods for CyType collections.</summary>
public static class CyLinqExtensions
{
    /// <summary>
    /// Creates a <see cref="CyList{T}"/> from an <see cref="IEnumerable{T}"/>.
    /// Elements are added by reference (not cloned).
    /// </summary>
    public static CyList<T> ToCyList<T>(this IEnumerable<T> source) where T : ICyType
    {
        ArgumentNullException.ThrowIfNull(source);
        var list = new CyList<T>();
        foreach (var item in source)
            list.Add(item);
        return list;
    }
}
