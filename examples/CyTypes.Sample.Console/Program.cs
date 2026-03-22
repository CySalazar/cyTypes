// CyTypes.Sample.Console — End-to-end walkthrough of cyTypes core features.
//
// Run: dotnet run --project examples/CyTypes.Sample.Console

using CyTypes.Collections;
using CyTypes.Core.Crypto.KeyExchange;
using CyTypes.Core.Crypto.Pqc;
using CyTypes.Core.KeyManagement;
using CyTypes.Core.Policy;
using CyTypes.Core.Policy.Components;
using CyTypes.Fhe.Crypto;
using CyTypes.Fhe.KeyManagement;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;
using CyTypes.Streams.File;

Console.WriteLine("=== cyTypes End-to-End Sample ===");
Console.WriteLine();

// ---------------------------------------------------------------
// 1. Encrypted primitives
// ---------------------------------------------------------------
Console.WriteLine("--- 1. Encrypted Primitives ---");

using var salary = new CyDecimal(85_000.50m);
using var name = new CyString("Jane Doe");
using var active = new CyBool(true);

Console.WriteLine($"  name     = {name}");       // redacted
Console.WriteLine($"  salary   = {salary}");     // redacted
Console.WriteLine($"  active   = {active}");     // redacted

// Arithmetic stays encrypted
using var bonus = new CyDecimal(5_000m);
using var total = salary + bonus;
Console.WriteLine($"  salary + bonus => IsCompromised: {total.IsCompromised}");
Console.WriteLine($"  Decrypted total: {total.ToInsecureDecimal():C}");
Console.WriteLine();

// ---------------------------------------------------------------
// 2. Security policies
// ---------------------------------------------------------------
Console.WriteLine("--- 2. Security Policies ---");

var strict = new SecurityPolicyBuilder()
    .WithName("StrictDemo")
    .WithTaintMode(TaintMode.Strict)
    .WithOverflowMode(OverflowMode.Checked)
    .WithMaxDecryptionCount(3)
    .WithAutoDestroy(true)
    .WithMemoryProtection(MemoryProtection.PinnedLocked)
    .Build();

using var pin = new CyInt(1234, strict);
Console.WriteLine($"  Policy: {pin.Policy}");
Console.WriteLine($"  Decrypt 1: {pin.ToInsecureInt()}");
Console.WriteLine($"  Decrypt 2: {pin.ToInsecureInt()}");
Console.WriteLine($"  Decrypt 3: {pin.ToInsecureInt()}");
try
{
    _ = pin.ToInsecureInt(); // 4th — exceeds MaxDecryptionCount
}
catch (Exception ex)
{
    Console.WriteLine($"  Decrypt 4: {ex.GetType().Name} — {ex.Message}");
}
Console.WriteLine();

// ---------------------------------------------------------------
// 3. Collections
// ---------------------------------------------------------------
Console.WriteLine("--- 3. Encrypted Collections ---");

using var scores = new CyList<CyInt>();
for (int i = 1; i <= 5; i++)
    scores.Add(new CyInt(i * 10));

Console.WriteLine($"  Scores count: {scores.Count}");
scores.ForEach(s => Console.Write($"  {s.ToInsecureInt()}"));
Console.WriteLine();

scores.RemoveAll(s => s.ToInsecureInt() < 30);
Console.WriteLine($"  After removing < 30: {scores.Count} items");
Console.WriteLine();

// ---------------------------------------------------------------
// 4. Key rotation and TTL
// ---------------------------------------------------------------
Console.WriteLine("--- 4. Key Rotation & TTL ---");

using var secret = new CyInt(42);
Console.WriteLine($"  Before rotation: {secret.ToInsecureInt()}");
secret.RotateKeyAndReEncrypt();
Console.WriteLine($"  After rotation:  {secret.ToInsecureInt()}");

using var km = new KeyManager(TimeSpan.FromSeconds(1));
Console.WriteLine($"  Key TTL: {km.Ttl}, expired: {km.IsExpired}");
Thread.Sleep(1100);
Console.WriteLine($"  After 1.1s: expired = {km.IsExpired}");
Console.WriteLine();

// ---------------------------------------------------------------
// 5. FHE — BFV integer arithmetic
// ---------------------------------------------------------------
Console.WriteLine("--- 5. FHE (BFV) ---");

using var bfvKm = new SealKeyManager();
bfvKm.Initialize(FheScheme.BFV, SealParameterPresets.Bfv128Bit());
using var bfvEngine = new SealBfvEngine(bfvKm);
FheEngineProvider.Configure(bfvEngine);

try
{
    var policy = SecurityPolicy.HomomorphicBasic;
    using var a = new CyInt(15, policy);
    using var b = new CyInt(27, policy);
    using var sum = a + b;
    using var product = a * b;

    Console.WriteLine($"  15 + 27 = {sum.ToInsecureInt()} (computed on ciphertext)");
    Console.WriteLine($"  15 * 27 = {product.ToInsecureInt()} (computed on ciphertext)");
}
finally
{
    FheEngineProvider.Reset();
}
Console.WriteLine();

// ---------------------------------------------------------------
// 6. Post-quantum key exchange
// ---------------------------------------------------------------
Console.WriteLine("--- 6. PQC Hybrid Key Exchange ---");

using var alice = new SessionKeyNegotiator();
using var bob = new SessionKeyNegotiator();

var aliceHs = alice.CreateHandshake();
var bobHs = bob.CreateHandshake();

var (aliceKey, mlKemCt) = alice.DeriveSessionKeyAsInitiator(bobHs);
using var bobKey = bob.DeriveSessionKeyAsResponder(aliceHs, mlKemCt);

using (aliceKey)
{
    bool match = aliceKey.AsReadOnlySpan().SequenceEqual(bobKey.AsReadOnlySpan());
    Console.WriteLine($"  ECDH P-256 + ML-KEM-1024 session keys match: {match}");
    Console.WriteLine($"  Session key: {aliceKey.Length * 8} bits");
}
Console.WriteLine();

// ---------------------------------------------------------------
// 7. Encrypted file I/O
// ---------------------------------------------------------------
Console.WriteLine("--- 7. Encrypted File Streaming ---");

var tempFile = Path.GetTempFileName();
try
{
    var fileKey = new byte[32];
    System.Security.Cryptography.RandomNumberGenerator.Fill(fileKey);
    var keyId = Guid.NewGuid();

    // Write
    using (var fs = CyFileStream.CreateWrite(tempFile, fileKey))
    {
        var data = System.Text.Encoding.UTF8.GetBytes("Confidential payload from cyTypes");
        fs.Write(data);
    }

    Console.WriteLine($"  Written encrypted file: {new FileInfo(tempFile).Length} bytes");

    // Read back
    using (var fs = CyFileStream.OpenRead(tempFile, fileKey))
    {
        var buffer = new byte[256];
        int read = fs.Read(buffer);
        var text = System.Text.Encoding.UTF8.GetString(buffer, 0, read);
        Console.WriteLine($"  Decrypted: \"{text}\"");
    }
}
finally
{
    File.Delete(tempFile);
}
Console.WriteLine();

// ---------------------------------------------------------------
Console.WriteLine("=== All features demonstrated successfully ===");
