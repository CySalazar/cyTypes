using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Fuzzing;

/// <summary>
/// Fuzz-style tests for AES-GCM decrypt and HKDF key derivation.
/// Verifies that arbitrary byte inputs either produce valid output or
/// throw CryptographicException — never crash, hang, or corrupt state.
/// </summary>
public class AesGcmFuzzTests
{
    private static readonly byte[] FixedKey = new byte[32];

    static AesGcmFuzzTests()
    {
        RandomNumberGenerator.Fill(FixedKey);
    }

    [Theory]
    [MemberData(nameof(RandomByteInputs))]
    public void Decrypt_ArbitraryBytes_NeverCrashes(byte[] fuzzInput)
    {
        var engine = new AesGcmEngine();
        try
        {
            engine.Decrypt(fuzzInput, FixedKey);
        }
        catch (CryptographicException)
        {
            // Expected for invalid ciphertext
        }
        catch (ArgumentException)
        {
            // Expected for inputs too short
        }
        // Any other exception type would fail the test
    }

    [Theory]
    [MemberData(nameof(RandomByteInputs))]
    public void HkdfDeriveKey_ArbitraryIkm_NeverCrashes(byte[] fuzzInput)
    {
        if (fuzzInput.Length == 0) return; // HKDF requires non-empty IKM

        var result = HkdfKeyDerivation.DeriveKey(fuzzInput, 32);
        result.Should().HaveCount(32);
    }

    [Theory]
    [MemberData(nameof(RandomByteInputs))]
    public void HmacCompute_ArbitraryData_NeverCrashes(byte[] fuzzInput)
    {
        var result = HmacComparer.Compute(FixedKey, fuzzInput);
        result.Should().HaveCount(64);
    }

    [Fact]
    public void Decrypt_EmptyInput_Throws()
    {
        var engine = new AesGcmEngine();
        var act = () => engine.Decrypt(Array.Empty<byte>(), FixedKey);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_MinimalSizeInput_Throws()
    {
        var engine = new AesGcmEngine();
        // Minimum valid size: nonce(12) + tag(16) = 28 bytes with 0-length plaintext
        var input = new byte[28];
        RandomNumberGenerator.Fill(input);
        var act = () => engine.Decrypt(input, FixedKey);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Decrypt_JustBelowMinSize_Throws()
    {
        var engine = new AesGcmEngine();
        var input = new byte[27];
        RandomNumberGenerator.Fill(input);
        var act = () => engine.Decrypt(input, FixedKey);
        act.Should().Throw<CryptographicException>();
    }

    public static IEnumerable<object[]> RandomByteInputs()
    {
        var rng = new Random(42); // Deterministic seed for reproducibility
        var sizes = new[] { 0, 1, 2, 11, 12, 15, 16, 27, 28, 29, 31, 32, 64, 128, 255, 256, 512, 1024, 4096 };

        foreach (var size in sizes)
        {
            var bytes = new byte[size];
            rng.NextBytes(bytes);
            yield return new object[] { bytes };
        }

        // Edge case: all zeros
        yield return new object[] { new byte[64] };

        // Edge case: all 0xFF
        var allOnes = new byte[64];
        Array.Fill(allOnes, (byte)0xFF);
        yield return new object[] { allOnes };
    }
}
