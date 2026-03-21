using System.Text.Json.Serialization;

namespace CyTypes.Security.Tests.Wycheproof;

public record WycheproofTestFile(
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("numberOfTests")] int NumberOfTests,
    [property: JsonPropertyName("testGroups")] WycheproofTestGroup[] TestGroups);

public record WycheproofTestGroup(
    [property: JsonPropertyName("ivSize")] int IvSize,
    [property: JsonPropertyName("keySize")] int KeySize,
    [property: JsonPropertyName("tagSize")] int TagSize,
    [property: JsonPropertyName("tests")] WycheproofTestCase[] Tests);

public record WycheproofTestCase(
    [property: JsonPropertyName("tcId")] int TcId,
    [property: JsonPropertyName("comment")] string Comment,
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("iv")] string Iv,
    [property: JsonPropertyName("aad")] string Aad,
    [property: JsonPropertyName("msg")] string Msg,
    [property: JsonPropertyName("ct")] string Ct,
    [property: JsonPropertyName("tag")] string Tag,
    [property: JsonPropertyName("result")] string Result);
