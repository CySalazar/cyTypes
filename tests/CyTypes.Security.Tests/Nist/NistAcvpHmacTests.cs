using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Nist;

/// <summary>
/// NIST ACVP test vectors for HMAC-SHA512.
/// Reference: FIPS 198-1, NIST CAVP HMAC test vectors.
/// </summary>
public class NistAcvpHmacTests
{
    /// <summary>
    /// HMAC-SHA512 test vectors from RFC 4231 (which references NIST FIPS 198-1).
    /// Each entry: Key (hex), Data (hex), Expected HMAC-SHA512 (hex).
    /// </summary>
    public static IEnumerable<object[]> HmacSha512Vectors()
    {
        // RFC 4231 Test Case 1
        yield return new object[]
        {
            "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B",
            "4869205468657265",
            "87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854"
        };

        // RFC 4231 Test Case 2 ("Jefe" / "what do ya want for nothing?")
        yield return new object[]
        {
            "4A656665",
            "7768617420646F2079612077616E7420666F72206E6F7468696E673F",
            "164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA2505549758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737"
        };

        // RFC 4231 Test Case 3 (key=0xAA x 20, data=0xDD x 50)
        yield return new object[]
        {
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            string.Concat(Enumerable.Repeat("DD", 50)),
            "FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB"
        };

        // RFC 4231 Test Case 4
        yield return new object[]
        {
            "0102030405060708090A0B0C0D0E0F10111213141516171819",
            string.Concat(Enumerable.Repeat("CD", 50)),
            "B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD"
        };

        // RFC 4231 Test Case 6 (131-byte key)
        yield return new object[]
        {
            string.Concat(Enumerable.Repeat("AA", 131)),
            "54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374",
            "80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598"
        };

        // RFC 4231 Test Case 7 (131-byte key, longer data)
        yield return new object[]
        {
            string.Concat(Enumerable.Repeat("AA", 131)),
            "5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C6172676572207468616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365642062792074686520484D414320616C676F726974686D2E",
            "E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58"
        };
    }

    [Theory]
    [MemberData(nameof(HmacSha512Vectors))]
    public void HmacSha512_Compute_MatchesNistVector(string keyHex, string dataHex, string expectedHex)
    {
        var key = Convert.FromHexString(keyHex);
        var data = Convert.FromHexString(dataHex);
        var expected = Convert.FromHexString(expectedHex);

        var actual = HmacComparer.Compute(key, data);

        actual.Should().Equal(expected,
            because: "HMAC-SHA512 computation must match NIST/RFC 4231 reference vector");
    }

    [Theory]
    [MemberData(nameof(HmacSha512Vectors))]
    public void HmacSha512_Verify_SucceedsForValidVector(string keyHex, string dataHex, string expectedHex)
    {
        var key = Convert.FromHexString(keyHex);
        var data = Convert.FromHexString(dataHex);
        var expected = Convert.FromHexString(expectedHex);

        HmacComparer.Verify(key, data, expected).Should().BeTrue(
            because: "HMAC-SHA512 verification must succeed for valid NIST/RFC 4231 vector");
    }

    [Theory]
    [MemberData(nameof(HmacSha512Vectors))]
    public void HmacSha512_Verify_FailsForTamperedMac(string keyHex, string dataHex, string expectedHex)
    {
        var key = Convert.FromHexString(keyHex);
        var data = Convert.FromHexString(dataHex);
        var tampered = Convert.FromHexString(expectedHex);
        tampered[0] ^= 0xFF;

        HmacComparer.Verify(key, data, tampered).Should().BeFalse(
            because: "HMAC-SHA512 verification must fail for tampered MAC");
    }
}
