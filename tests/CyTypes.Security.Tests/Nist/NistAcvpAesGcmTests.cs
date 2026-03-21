using System.Security.Cryptography;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Nist;

/// <summary>
/// NIST ACVP (Automated Cryptographic Validation Protocol) test vectors for AES-256-GCM.
/// Reference: NIST SP 800-38D, ACVTS repository (github.com/usnistgov/ACVTS).
/// These vectors validate encrypt/decrypt correctness against the NIST reference.
/// </summary>
public class NistAcvpAesGcmTests
{
    /// <summary>
    /// NIST SP 800-38D AES-256-GCM test vectors.
    /// Source: NIST CAVP AES-GCM test vectors (GCMEncryptDecrypt256.rsp).
    /// Each entry: Key, IV, Plaintext, AAD, Ciphertext, Tag (all hex).
    /// </summary>
    public static IEnumerable<object[]> AesGcm256Vectors()
    {
        // NIST SP 800-38D Test Case 13 (256-bit key, no plaintext, no AAD)
        yield return new object[]
        {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "530F8AFBC74536B9A963B4F1C4CB738B"
        };

        // NIST SP 800-38D Test Case 14 (256-bit key, with plaintext, no AAD)
        yield return new object[]
        {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "CEA7403D4D606B6E074EC5D3BAF39D18",
            "D0D1C8A799996BF0265B98B5D48AB919"
        };

        // NIST SP 800-38D Test Case 15 (256-bit key, with plaintext and AAD)
        yield return new object[]
        {
            "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
            "CAFEBABEFACEDBADDECAF888",
            "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255",
            "",
            "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD",
            "B094DAC5D93471BDEC1A502270E3CC6C"
        };

        // NIST SP 800-38D Test Case 16 (256-bit key, with AAD)
        yield return new object[]
        {
            "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
            "CAFEBABEFACEDBADDECAF888",
            "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39",
            "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
            "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662",
            "76FC6ECE0F4E1768CDDF8853BB2D551B"
        };

        // NIST SP 800-38D Test Case 15 variant: single-block plaintext
        yield return new object[]
        {
            "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
            "CAFEBABEFACEDBADDECAF888",
            "D9313225F88406E5A55909C5AFF5269A",
            "",
            "522DC1F099567D07F47F37A32A84427D",
            "7EA353DA7E9241A1D90D693A4954186B"
        };
    }

    [Theory]
    [MemberData(nameof(AesGcm256Vectors))]
    public void AesGcm256_Decrypt_MatchesNistVector(
        string keyHex, string ivHex, string ptHex, string aadHex, string ctHex, string tagHex)
    {
        var key = Convert.FromHexString(keyHex);
        var iv = Convert.FromHexString(ivHex);
        var ct = Convert.FromHexString(ctHex);
        var tag = Convert.FromHexString(tagHex);
        var expectedPt = Convert.FromHexString(ptHex);
        var aad = string.IsNullOrEmpty(aadHex) ? ReadOnlySpan<byte>.Empty : Convert.FromHexString(aadHex);

        // Reconstruct engine format: [iv:12][ct:N][tag:16]
        var engineCt = new byte[iv.Length + ct.Length + tag.Length];
        iv.CopyTo(engineCt, 0);
        ct.CopyTo(engineCt, iv.Length);
        tag.CopyTo(engineCt, iv.Length + ct.Length);

        var engine = new AesGcmEngine();
        var plaintext = engine.Decrypt(engineCt, key, aad);

        plaintext.Should().Equal(expectedPt,
            because: "NIST SP 800-38D AES-256-GCM decryption must match reference vector");
    }

    [Theory]
    [MemberData(nameof(AesGcm256Vectors))]
    public void AesGcm256_EncryptDecrypt_Roundtrip(
        string keyHex, string _ivHex, string ptHex, string aadHex, string _ctHex, string _tagHex)
    {
        var key = Convert.FromHexString(keyHex);
        var plaintext = Convert.FromHexString(ptHex);
        var aad = string.IsNullOrEmpty(aadHex) ? ReadOnlySpan<byte>.Empty : Convert.FromHexString(aadHex);

        var engine = new AesGcmEngine();
        var ciphertext = engine.Encrypt(plaintext, key, aad);
        var decrypted = engine.Decrypt(ciphertext, key, aad);

        decrypted.Should().Equal(plaintext,
            because: "AES-256-GCM encrypt/decrypt roundtrip must preserve plaintext");

        _ = _ivHex;
        _ = _ctHex;
        _ = _tagHex;
    }

    [Fact]
    public void AesGcm256_TamperedCiphertext_ThrowsCryptographicException()
    {
        var key = Convert.FromHexString("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308");
        var iv = Convert.FromHexString("CAFEBABEFACEDBADDECAF888");
        var ct = Convert.FromHexString("522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD");
        var tag = Convert.FromHexString("B094DAC5D93471BDEC1A502270E3CC6C");

        var engineCt = new byte[iv.Length + ct.Length + tag.Length];
        iv.CopyTo(engineCt, 0);
        ct.CopyTo(engineCt, iv.Length);
        tag.CopyTo(engineCt, iv.Length + ct.Length);

        // Tamper with ciphertext
        engineCt[15] ^= 0xFF;

        var engine = new AesGcmEngine();
        var act = () => engine.Decrypt(engineCt, key);

        act.Should().Throw<CryptographicException>(
            because: "NIST: tampered AES-GCM ciphertext must be rejected");
    }
}
