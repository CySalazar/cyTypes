namespace CyTypes.Streams;

/// <summary>
/// Maps CyType concrete types to 16-bit type identifiers for stream framing.
/// </summary>
public static class CyTypeIds
{
    /// <summary>CyInt type identifier.</summary>
    public const ushort CyInt = 0x0001;
    /// <summary>CyLong type identifier.</summary>
    public const ushort CyLong = 0x0002;
    /// <summary>CyDouble type identifier.</summary>
    public const ushort CyDouble = 0x0003;
    /// <summary>CyFloat type identifier.</summary>
    public const ushort CyFloat = 0x0004;
    /// <summary>CyDecimal type identifier.</summary>
    public const ushort CyDecimal = 0x0005;
    /// <summary>CyBool type identifier.</summary>
    public const ushort CyBool = 0x0006;
    /// <summary>CyString type identifier.</summary>
    public const ushort CyString = 0x0007;
    /// <summary>CyBytes type identifier.</summary>
    public const ushort CyBytes = 0x0008;
    /// <summary>CyGuid type identifier.</summary>
    public const ushort CyGuid = 0x0009;
    /// <summary>CyDateTime type identifier.</summary>
    public const ushort CyDateTime = 0x000A;

    private static readonly Dictionary<Type, ushort> TypeMap = new()
    {
        [typeof(Primitives.CyInt)] = CyInt,
        [typeof(Primitives.CyLong)] = CyLong,
        [typeof(Primitives.CyDouble)] = CyDouble,
        [typeof(Primitives.CyFloat)] = CyFloat,
        [typeof(Primitives.CyDecimal)] = CyDecimal,
        [typeof(Primitives.CyBool)] = CyBool,
        [typeof(Primitives.CyString)] = CyString,
        [typeof(Primitives.CyBytes)] = CyBytes,
        [typeof(Primitives.CyGuid)] = CyGuid,
        [typeof(Primitives.CyDateTime)] = CyDateTime,
    };

    /// <summary>Gets the type ID for a CyType type parameter.</summary>
    public static ushort GetTypeId<T>()
    {
        if (TypeMap.TryGetValue(typeof(T), out var id))
            return id;
        throw new NotSupportedException($"Type {typeof(T).Name} is not a supported CyType for stream serialization.");
    }

    /// <summary>Gets the type ID for a CyType runtime type.</summary>
    public static ushort GetTypeId(Type type)
    {
        if (TypeMap.TryGetValue(type, out var id))
            return id;
        throw new NotSupportedException($"Type {type.Name} is not a supported CyType for stream serialization.");
    }
}
