namespace CyTypes.Core.Crypto.Interfaces;

/// <summary>
/// Defines binary serialization and deserialization for primitive types.
/// </summary>
public interface ISecureSerializer
{
    /// <summary>
    /// Serializes a value of type <typeparamref name="T"/> to a byte array.
    /// </summary>
    /// <typeparam name="T">The type of value to serialize.</typeparam>
    /// <param name="value">The value to serialize.</param>
    /// <returns>The serialized byte representation.</returns>
    byte[] Serialize<T>(T value);

    /// <summary>
    /// Deserializes a byte span back to a value of type <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The type of value to deserialize.</typeparam>
    /// <param name="data">The byte data to deserialize.</param>
    /// <returns>The deserialized value.</returns>
    T Deserialize<T>(ReadOnlySpan<byte> data);
}
