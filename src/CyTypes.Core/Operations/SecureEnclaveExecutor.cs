using System.Numerics;
using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.Interfaces;

namespace CyTypes.Core.Operations;

/// <summary>
/// Executes arithmetic and comparison operations by decrypting operands in a secure enclave, performing the operation in plaintext, and re-encrypting the result.
/// </summary>
public sealed class SecureEnclaveExecutor
{
    private readonly ICryptoEngine _cryptoEngine;
    private readonly ISecureSerializer _serializer;

    /// <summary>Initializes a new executor with the specified crypto engine and the default binary serializer.</summary>
    /// <param name="cryptoEngine">The cryptographic engine used for encrypt/decrypt operations.</param>
    public SecureEnclaveExecutor(ICryptoEngine cryptoEngine)
        : this(cryptoEngine, new BinarySerializer())
    {
    }

    /// <summary>Initializes a new executor with the specified crypto engine and serializer.</summary>
    /// <param name="cryptoEngine">The cryptographic engine used for encrypt/decrypt operations.</param>
    /// <param name="serializer">The serializer used to convert between typed values and byte arrays.</param>
    public SecureEnclaveExecutor(ICryptoEngine cryptoEngine, ISecureSerializer serializer)
    {
        _cryptoEngine = cryptoEngine ?? throw new ArgumentNullException(nameof(cryptoEngine));
        _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
    }

    /// <summary>Maximum allowed ciphertext size to prevent excessive memory allocation (16 MB).</summary>
    private const int MaxCiphertextSize = 16 * 1024 * 1024;

    /// <summary>Decrypts two ciphertexts, adds the plaintext values, and returns the encrypted result.</summary>
    public byte[] Add<T>(byte[] encryptedA, byte[] encryptedB, ReadOnlySpan<byte> key)
        where T : INumber<T>
    {
        return ExecuteBinaryOp<T>(encryptedA, encryptedB, key, (a, b) => a + b);
    }

    /// <summary>Decrypts two ciphertexts, subtracts the plaintext values, and returns the encrypted result.</summary>
    public byte[] Subtract<T>(byte[] encryptedA, byte[] encryptedB, ReadOnlySpan<byte> key)
        where T : INumber<T>
    {
        return ExecuteBinaryOp<T>(encryptedA, encryptedB, key, (a, b) => a - b);
    }

    /// <summary>Decrypts two ciphertexts, multiplies the plaintext values, and returns the encrypted result.</summary>
    public byte[] Multiply<T>(byte[] encryptedA, byte[] encryptedB, ReadOnlySpan<byte> key)
        where T : INumber<T>
    {
        return ExecuteBinaryOp<T>(encryptedA, encryptedB, key, (a, b) => a * b);
    }

    /// <summary>Decrypts two ciphertexts, divides the plaintext values, and returns the encrypted result.</summary>
    public byte[] Divide<T>(byte[] encryptedA, byte[] encryptedB, ReadOnlySpan<byte> key)
        where T : INumber<T>
    {
        return ExecuteBinaryOp<T>(encryptedA, encryptedB, key, (a, b) => a / b);
    }

    /// <summary>Decrypts two ciphertexts, computes the modulo of the plaintext values, and returns the encrypted result.</summary>
    public byte[] Modulo<T>(byte[] encryptedA, byte[] encryptedB, ReadOnlySpan<byte> key)
        where T : INumber<T>, IModulusOperators<T, T, T>
    {
        return ExecuteBinaryOp<T>(encryptedA, encryptedB, key, (a, b) => a % b);
    }

    /// <summary>Decrypts two ciphertexts and returns whether the plaintext values are equal.</summary>
    public bool Compare<T>(byte[] encryptedA, byte[] encryptedB, ReadOnlySpan<byte> key)
        where T : INumber<T>, IComparisonOperators<T, T, bool>
    {
        ValidateInputs(encryptedA, encryptedB);
        var plaintextA = _cryptoEngine.Decrypt(encryptedA, key);
        var plaintextB = _cryptoEngine.Decrypt(encryptedB, key);

        try
        {
            var a = _serializer.Deserialize<T>(plaintextA);
            var b = _serializer.Deserialize<T>(plaintextB);
            return a == b;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextA);
            CryptographicOperations.ZeroMemory(plaintextB);
        }
    }

    private static void ValidateInputs(byte[] encryptedA, byte[] encryptedB)
    {
        ArgumentNullException.ThrowIfNull(encryptedA);
        ArgumentNullException.ThrowIfNull(encryptedB);
        if (encryptedA.Length > MaxCiphertextSize)
            throw new ArgumentException($"Ciphertext exceeds maximum allowed size of {MaxCiphertextSize} bytes.", nameof(encryptedA));
        if (encryptedB.Length > MaxCiphertextSize)
            throw new ArgumentException($"Ciphertext exceeds maximum allowed size of {MaxCiphertextSize} bytes.", nameof(encryptedB));
    }

    private byte[] ExecuteBinaryOp<T>(byte[] encryptedA, byte[] encryptedB, ReadOnlySpan<byte> key, Func<T, T, T> operation)
        where T : INumber<T>
    {
        ValidateInputs(encryptedA, encryptedB);
        var plaintextA = _cryptoEngine.Decrypt(encryptedA, key);
        var plaintextB = _cryptoEngine.Decrypt(encryptedB, key);

        try
        {
            var a = _serializer.Deserialize<T>(plaintextA);
            var b = _serializer.Deserialize<T>(plaintextB);
            var result = operation(a, b);
            var resultBytes = _serializer.Serialize(result);

            try
            {
                return _cryptoEngine.Encrypt(resultBytes, key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(resultBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextA);
            CryptographicOperations.ZeroMemory(plaintextB);
        }
    }
}
