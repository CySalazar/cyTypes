using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using CyTypes.Core.Crypto.KeyExchange;
using SharpFuzz;

namespace CyTypes.Security.Tests.Fuzzing;

/// <summary>
/// Entry point for AFL/libFuzzer via SharpFuzz.
/// Usage: dotnet run --project CyTypes.Security.Tests -- --fuzz [target]
/// Targets: decrypt, hkdf, hmac, chunked-decrypt, handshake-deserialize, binary-deserialize
/// </summary>
public static class FuzzingProgram
{
    private static readonly byte[] FuzzKey = new byte[32];

    static FuzzingProgram()
    {
        // Fixed key for reproducible fuzzing
        for (int i = 0; i < 32; i++) FuzzKey[i] = (byte)i;
    }

    public static void RunFuzzer(string target)
    {
        switch (target.ToLowerInvariant())
        {
            case "decrypt":
                Fuzzer.Run(stream =>
                {
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    var input = ms.ToArray();
                    try
                    {
                        var engine = new AesGcmEngine();
                        engine.Decrypt(input, FuzzKey);
                    }
                    catch (CryptographicException) { }
                    catch (ArgumentException) { }
                });
                break;

            case "hkdf":
                Fuzzer.Run(stream =>
                {
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    var input = ms.ToArray();
                    if (input.Length > 0)
                        HkdfKeyDerivation.DeriveKey(input, 32);
                });
                break;

            case "hmac":
                Fuzzer.Run(stream =>
                {
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    var input = ms.ToArray();
                    HmacComparer.Compute(FuzzKey, input);
                });
                break;

            case "chunked-decrypt":
                Fuzzer.Run(stream =>
                {
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    var input = ms.ToArray();
                    if (input.Length == 0) return;
                    using var engine = new ChunkedCryptoEngine(FuzzKey);
                    try
                    {
                        engine.DecryptChunk(input, 0, out _);
                    }
                    catch (CryptographicException) { }
                    catch (ArgumentException) { }
                });
                break;

            case "handshake-deserialize":
                Fuzzer.Run(stream =>
                {
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    var input = ms.ToArray();
                    try
                    {
                        HandshakeMessage.Deserialize(input);
                    }
                    catch (ArgumentException) { }
                });
                break;

            case "binary-deserialize":
                Fuzzer.Run(stream =>
                {
                    using var ms = new MemoryStream();
                    stream.CopyTo(ms);
                    var input = ms.ToArray();
                    try
                    {
                        new BinarySerializer().Deserialize<string>(input);
                    }
                    catch (ArgumentException) { }
                });
                break;

            default:
                Console.Error.WriteLine($"Unknown fuzz target: {target}");
                Console.Error.WriteLine("Available targets: decrypt, hkdf, hmac, chunked-decrypt, handshake-deserialize, binary-deserialize");
                break;
        }
    }
}
