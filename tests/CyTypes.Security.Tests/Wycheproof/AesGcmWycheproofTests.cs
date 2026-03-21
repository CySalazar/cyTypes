using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using CyTypes.Core.Crypto;
using FluentAssertions;
using Xunit;

namespace CyTypes.Security.Tests.Wycheproof;

public class AesGcmWycheproofTests
{
    private static readonly Lazy<List<object[]>> TestCasesLazy = new(LoadTestCases);

    public static IEnumerable<object[]> ValidDecryptVectors => TestCasesLazy.Value.Where(tc => (string)tc[1] == "valid");
    public static IEnumerable<object[]> InvalidDecryptVectors => TestCasesLazy.Value.Where(tc => (string)tc[1] == "invalid");

    private static List<object[]> LoadTestCases()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(
            "CyTypes.Security.Tests.Wycheproof.TestVectors.aes_gcm_test.json")
            ?? throw new InvalidOperationException("Wycheproof test vector file not found as embedded resource.");

        var testFile = JsonSerializer.Deserialize<WycheproofTestFile>(stream)
            ?? throw new InvalidOperationException("Failed to deserialize Wycheproof test vectors.");

        var cases = new List<object[]>();
        foreach (var group in testFile.TestGroups)
        {
            // Filter: AES-256-GCM with 96-bit IV and 128-bit tag
            if (group.KeySize != 256 || group.IvSize != 96 || group.TagSize != 128)
                continue;

            foreach (var tc in group.Tests)
            {
                cases.Add(new object[] { tc.TcId, tc.Result, tc.Key, tc.Iv, tc.Aad, tc.Msg, tc.Ct, tc.Tag, tc.Comment });
            }
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(ValidDecryptVectors))]
    public void Decrypt_ValidVector_ReturnsExpectedPlaintext(
        int tcId, string _result, string keyHex, string ivHex, string aadHex,
        string msgHex, string ctHex, string tagHex, string comment)
    {
        var engine = new AesGcmEngine();
        var key = Convert.FromHexString(keyHex);
        var iv = Convert.FromHexString(ivHex);
        var ct = Convert.FromHexString(ctHex);
        var tag = Convert.FromHexString(tagHex);
        var expectedMsg = Convert.FromHexString(msgHex);
        var aadBytes = string.IsNullOrEmpty(aadHex) ? Array.Empty<byte>() : Convert.FromHexString(aadHex);

        // Reconstruct engine format: [iv:12][ct:N][tag:16]
        var engineCiphertext = new byte[iv.Length + ct.Length + tag.Length];
        iv.CopyTo(engineCiphertext, 0);
        ct.CopyTo(engineCiphertext, iv.Length);
        tag.CopyTo(engineCiphertext, iv.Length + ct.Length);

        var plaintext = engine.Decrypt(engineCiphertext, key, aadBytes);

        plaintext.Should().Equal(expectedMsg,
            because: $"Wycheproof tcId={tcId}: {comment}");
        _ = _result; // Used for filtering in MemberData
    }

    [Theory]
    [MemberData(nameof(InvalidDecryptVectors))]
    public void Decrypt_InvalidVector_ThrowsCryptographicException(
        int tcId, string result, string keyHex, string ivHex, string aadHex,
        string _msgHex, string ctHex, string tagHex, string comment)
    {
        var engine = new AesGcmEngine();
        var key = Convert.FromHexString(keyHex);
        var iv = Convert.FromHexString(ivHex);
        var ct = Convert.FromHexString(ctHex);
        var tag = Convert.FromHexString(tagHex);
        var aadBytes = string.IsNullOrEmpty(aadHex) ? Array.Empty<byte>() : Convert.FromHexString(aadHex);

        var engineCiphertext = new byte[iv.Length + ct.Length + tag.Length];
        iv.CopyTo(engineCiphertext, 0);
        ct.CopyTo(engineCiphertext, iv.Length);
        tag.CopyTo(engineCiphertext, iv.Length + ct.Length);

        var act = () => engine.Decrypt(engineCiphertext, key, aadBytes);

        act.Should().Throw<CryptographicException>(
            because: $"Wycheproof tcId={tcId} (result={result}): {comment}");
        _ = _msgHex; // Not needed for invalid vector validation
    }
}
