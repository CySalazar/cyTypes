using System.Globalization;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Rfc;

/// <summary>
/// HKDF-SHA512 test vectors based on RFC 5869 structure.
/// RFC 5869 Appendix A provides SHA-256 vectors only; these SHA-512 outputs
/// are precomputed using the .NET HKDF reference implementation and verified
/// for cross-platform consistency.
/// </summary>
public class HkdfSha512RfcVectorTests
{
    public static IEnumerable<object[]> HkdfVectors()
    {
        // Test Case 1: Basic extraction and expansion (RFC 5869 A.1 structure, SHA-512)
        yield return new object[]
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", // IKM (22 bytes)
            "000102030405060708090a0b0c",                       // salt
            "f0f1f2f3f4f5f6f7f8f9",                             // info
            42,                                                  // L
            "832390086CDA71FB47625BB5CEB168E4C8E26A1A16ED34D9FC7FE92C1481579338DA362CB8D9F925D7CB"
        };

        // Test Case 2: Longer inputs (RFC 5869 A.2 structure, SHA-512)
        yield return new object[]
        {
            string.Concat(Enumerable.Range(0, 80).Select(i => i.ToString("x2", CultureInfo.InvariantCulture))),
            string.Concat(Enumerable.Range(0x60, 80).Select(i => i.ToString("x2", CultureInfo.InvariantCulture))),
            string.Concat(Enumerable.Range(0xb0, 80).Select(i => i.ToString("x2", CultureInfo.InvariantCulture))),
            82,
            "CE6C97192805B346E6161E821ED165673B84F400A2B514B2FE23D84CD189DDF1B695B48CBD1C8388441137B3CE28F16AA64BA33BA466B24DF6CFCB021ECFF235F6A2056CE3AF1DE44D572097A8505D9E7A93"
        };

        // Test Case 3: No salt, no info (RFC 5869 A.3 structure, SHA-512)
        yield return new object[]
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", // IKM
            "",                                                  // no salt
            "",                                                  // no info
            42,
            "F5FA02B18298A72A8C23898A8703472C6EB179DC204C03425C970E3B164BF90FFF22D04836D0E2343BAC"
        };
    }

    [Theory]
    [MemberData(nameof(HkdfVectors))]
    public void DeriveKey_WithRfcVector_ProducesExpectedOutput(
        string ikmHex, string saltHex, string infoHex, int length, string expectedOkmHex)
    {
        var ikm = Convert.FromHexString(ikmHex);
        var salt = string.IsNullOrEmpty(saltHex) ? ReadOnlySpan<byte>.Empty : Convert.FromHexString(saltHex);
        var info = string.IsNullOrEmpty(infoHex) ? ReadOnlySpan<byte>.Empty : Convert.FromHexString(infoHex);

        var okm = HkdfKeyDerivation.DeriveKey(ikm, length, salt, info);

        Convert.ToHexString(okm).Should().BeEquivalentTo(expectedOkmHex);
    }

    [Fact]
    public void DeriveKey_SameInputs_ProducesDeterministicOutput()
    {
        var ikm = new byte[32];
        Array.Fill(ikm, (byte)0xaa);
        var salt = new byte[] { 0x01, 0x02, 0x03 };
        var info = new byte[] { 0x04, 0x05, 0x06 };

        var result1 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, info);
        var result2 = HkdfKeyDerivation.DeriveKey(ikm, 32, salt, info);

        result1.Should().Equal(result2);
    }
}
