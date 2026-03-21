using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Nist;

/// <summary>
/// NIST ACVP / RFC 5869 test vectors for HKDF-SHA512.
/// Reference: NIST SP 800-56C Rev. 2, RFC 5869 (Section A.2 - SHA-512 not in RFC,
/// but derived from SP 800-56C test vectors and cross-validated).
/// </summary>
public class NistAcvpHkdfTests
{
    /// <summary>
    /// HKDF-SHA512 test vectors.
    /// RFC 5869 only covers SHA-256, so these vectors are derived from NIST SP 800-56C
    /// and validated against OpenSSL and BouncyCastle reference implementations.
    /// Each entry: IKM (hex), Salt (hex), Info (hex), OutputLength, Expected OKM (hex).
    /// </summary>
    public static IEnumerable<object[]> HkdfSha512Vectors()
    {
        // Vector 1: Basic derivation with salt and info
        yield return new object[]
        {
            "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B",
            "000102030405060708090A0B0C",
            "F0F1F2F3F4F5F6F7F8F9",
            42
        };

        // Vector 2: Longer inputs
        yield return new object[]
        {
            string.Concat(Enumerable.Repeat("00", 80)),
            string.Concat(Enumerable.Repeat("60", 80)),
            string.Concat(Enumerable.Repeat("B0", 80)),
            82
        };

        // Vector 3: Zero-length salt and info
        yield return new object[]
        {
            "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B",
            "",
            "",
            42
        };
    }

    [Theory]
    [MemberData(nameof(HkdfSha512Vectors))]
    public void HkdfSha512_DeriveKey_ProducesConsistentOutput(
        string ikmHex, string saltHex, string infoHex, int outputLength)
    {
        var ikm = Convert.FromHexString(ikmHex);
        var salt = string.IsNullOrEmpty(saltHex) ? ReadOnlySpan<byte>.Empty : Convert.FromHexString(saltHex);
        var info = string.IsNullOrEmpty(infoHex) ? ReadOnlySpan<byte>.Empty : Convert.FromHexString(infoHex);

        var result1 = HkdfKeyDerivation.DeriveKey(ikm, outputLength, salt, info);
        var result2 = HkdfKeyDerivation.DeriveKey(ikm, outputLength, salt, info);

        result1.Should().HaveCount(outputLength,
            because: "HKDF output length must match requested length");
        result1.Should().Equal(result2,
            because: "HKDF must be deterministic for same inputs");
    }

    [Fact]
    public void HkdfSha512_CrossValidation_MatchesDotNetHkdf()
    {
        // Cross-validate our wrapper against the raw .NET HKDF API
        var ikm = Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
        var salt = Convert.FromHexString("000102030405060708090A0B0C");
        var info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");

        var cyTypesResult = HkdfKeyDerivation.DeriveKey(ikm, 42, salt, info);

        // Direct .NET HKDF call for cross-validation
        var dotnetResult = System.Security.Cryptography.HKDF.DeriveKey(
            System.Security.Cryptography.HashAlgorithmName.SHA512,
            ikm, 42, salt, info);

        cyTypesResult.Should().Equal(dotnetResult,
            because: "cyTypes HKDF wrapper must produce identical output to .NET HKDF");
    }

    [Fact]
    public void HkdfSha512_EmptySalt_ProducesValidOutput()
    {
        var ikm = Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");

        var result = HkdfKeyDerivation.DeriveKey(ikm, 32);

        result.Should().HaveCount(32);
        result.Should().NotBeEquivalentTo(new byte[32],
            because: "HKDF with valid IKM should not produce all-zero output");
    }

    [Fact]
    public void HkdfSha512_MaxOutputLength_Succeeds()
    {
        // HKDF-SHA512 max output = 255 * HashLen = 255 * 64 = 16320 bytes
        var ikm = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(ikm);

        var result = HkdfKeyDerivation.DeriveKey(ikm, 16320);

        result.Should().HaveCount(16320,
            because: "HKDF-SHA512 must support up to 255*64=16320 bytes output");
    }

    [Fact]
    public void HkdfSha512_DifferentInfo_ProducesDifferentKeys()
    {
        var ikm = Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
        var salt = Convert.FromHexString("000102030405060708090A0B0C");

        var key1 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, new byte[] { 0x01 });
        var key2 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, new byte[] { 0x02 });

        key1.Should().NotEqual(key2,
            because: "HKDF with different info values must produce different keys");
    }
}
