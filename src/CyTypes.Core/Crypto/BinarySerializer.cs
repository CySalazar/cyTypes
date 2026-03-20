using System.Text;
using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Core.Crypto;

/// <summary>
/// Default implementation of <see cref="ISecureSerializer"/> with type-dispatch
/// for all primitive types used by cyTypes.
/// </summary>
public sealed class BinarySerializer : ISecureSerializer
{
    /// <summary>Maximum allowed serialized size for variable-length types (16 MB).</summary>
    public const int MaxVariableLengthBytes = 16 * 1024 * 1024;

    /// <inheritdoc />
    public byte[] Serialize<T>(T value)
    {
        return value switch
        {
            int i => BitConverter.GetBytes(i),
            long l => BitConverter.GetBytes(l),
            double d => BitConverter.GetBytes(d),
            float f => BitConverter.GetBytes(f),
            decimal m => SerializeDecimal(m),
            bool b => BitConverter.GetBytes(b),
            string s => Encoding.UTF8.GetBytes(s),
            byte[] bytes => (byte[])bytes.Clone(),
            Guid g => g.ToByteArray(),
            DateTime dt => BitConverter.GetBytes(dt.Ticks),
            _ => throw new NotSupportedException($"Type {typeof(T)} is not supported for serialization.")
        };
    }

    /// <inheritdoc />
    public T Deserialize<T>(ReadOnlySpan<byte> data)
    {
        if (typeof(T) == typeof(int))
        {
            if (data.Length < 4) throw new ArgumentException($"int deserialization requires 4 bytes, got {data.Length}.", nameof(data));
            return (T)(object)BitConverter.ToInt32(data);
        }
        if (typeof(T) == typeof(long))
        {
            if (data.Length < 8) throw new ArgumentException($"long deserialization requires 8 bytes, got {data.Length}.", nameof(data));
            return (T)(object)BitConverter.ToInt64(data);
        }
        if (typeof(T) == typeof(double))
        {
            if (data.Length < 8) throw new ArgumentException($"double deserialization requires 8 bytes, got {data.Length}.", nameof(data));
            return (T)(object)BitConverter.ToDouble(data);
        }
        if (typeof(T) == typeof(float))
        {
            if (data.Length < 4) throw new ArgumentException($"float deserialization requires 4 bytes, got {data.Length}.", nameof(data));
            return (T)(object)BitConverter.ToSingle(data);
        }
        if (typeof(T) == typeof(decimal))
        {
            if (data.Length < 16) throw new ArgumentException($"decimal deserialization requires 16 bytes, got {data.Length}.", nameof(data));
            var bits = new int[4];
            for (var i = 0; i < 4; i++)
                bits[i] = BitConverter.ToInt32(data.Slice(i * 4, 4));
            return (T)(object)new decimal(bits);
        }
        if (typeof(T) == typeof(bool))
        {
            if (data.Length < 1) throw new ArgumentException($"bool deserialization requires 1 byte, got {data.Length}.", nameof(data));
            return (T)(object)BitConverter.ToBoolean(data);
        }
        if (typeof(T) == typeof(string))
        {
            if (data.Length > MaxVariableLengthBytes)
                throw new ArgumentException($"String deserialization data exceeds maximum allowed size ({MaxVariableLengthBytes} bytes), got {data.Length}.", nameof(data));
            return (T)(object)Encoding.UTF8.GetString(data);
        }
        if (typeof(T) == typeof(byte[]))
        {
            if (data.Length > MaxVariableLengthBytes)
                throw new ArgumentException($"Byte array deserialization data exceeds maximum allowed size ({MaxVariableLengthBytes} bytes), got {data.Length}.", nameof(data));
            return (T)(object)data.ToArray();
        }
        if (typeof(T) == typeof(Guid))
        {
            if (data.Length < 16) throw new ArgumentException($"Guid deserialization requires 16 bytes, got {data.Length}.", nameof(data));
            return (T)(object)new Guid(data[..16]);
        }
        if (typeof(T) == typeof(DateTime))
        {
            if (data.Length < 8) throw new ArgumentException($"DateTime deserialization requires 8 bytes, got {data.Length}.", nameof(data));
            return (T)(object)new DateTime(BitConverter.ToInt64(data), DateTimeKind.Utc);
        }

        throw new NotSupportedException($"Type {typeof(T)} is not supported for deserialization.");
    }

    private static byte[] SerializeDecimal(decimal m)
    {
        var bits = decimal.GetBits(m);
        var result = new byte[16];
        for (var i = 0; i < 4; i++)
            BitConverter.GetBytes(bits[i]).CopyTo(result, i * 4);
        return result;
    }
}
