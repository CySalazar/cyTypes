using System.Security.Cryptography;
using System.Text;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;
using CyTypes.Streams;
using CyTypes.Streams.File;

namespace CyTypes.Examples.Demos;

public static class StreamEncryption
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 14: Stream Encryption - CyTypes.Streams");

        ConsoleHelpers.PrintNote("CyTypes.Streams provides AES-256-GCM chunked encryption for streams and files.");
        ConsoleHelpers.PrintNote("Data is encrypted in chunks with sequence numbers to prevent reordering attacks.");
        Console.WriteLine();

        // --- File encryption with passphrase ---
        ConsoleHelpers.PrintSubHeader("Part 1: Encrypted File I/O with CyFileStream");

        var tempFile = Path.Combine(Path.GetTempPath(), $"cytypes_demo_{Guid.NewGuid():N}.cyf");

        ConsoleHelpers.PrintCode("var path = \"secret_data.cyf\";");
        ConsoleHelpers.PrintCode("using (var writer = CyFileStream.CreateWrite(path, \"my-passphrase\"))");
        ConsoleHelpers.PrintCode("{");
        ConsoleHelpers.PrintCode("    writer.Write(Encoding.UTF8.GetBytes(\"Sensitive payload\"));");
        ConsoleHelpers.PrintCode("}");

        // Write encrypted file
        using (var writer = CyFileStream.CreateWrite(tempFile, "demo-passphrase"))
        {
            var data = Encoding.UTF8.GetBytes("This is sensitive data protected by CyTypes stream encryption.");
            writer.Write(data);
        }

        var fileSize = new FileInfo(tempFile).Length;
        ConsoleHelpers.PrintSecure($"File written: {fileSize} bytes (encrypted + header + footer)");
        ConsoleHelpers.PrintNote("The file contains: header (key ID, chunk size, flags) + encrypted chunks + HMAC footer.");
        Console.WriteLine();

        // Read encrypted file
        ConsoleHelpers.PrintCode("using (var reader = CyFileStream.OpenRead(path, \"my-passphrase\"))");
        ConsoleHelpers.PrintCode("{");
        ConsoleHelpers.PrintCode("    var bytesRead = reader.Read(buffer);");
        ConsoleHelpers.PrintCode("}");

        using (var reader = CyFileStream.OpenRead(tempFile, "demo-passphrase"))
        {
            var buffer = new byte[1024];
            var bytesRead = reader.Read(buffer);
            var plaintext = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            ConsoleHelpers.PrintRisk($"Decrypted: \"{plaintext}\"");
        }

        ConsoleHelpers.PrintNote("Passphrase-based keys are derived via HKDF using the file's key ID as salt.");
        Console.WriteLine();

        // --- Raw key file encryption ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Part 2: File Encryption with Raw 256-bit Key");

        var tempFile2 = Path.Combine(Path.GetTempPath(), $"cytypes_demo_{Guid.NewGuid():N}.cyf");
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        ConsoleHelpers.PrintCode("var key = new byte[32];");
        ConsoleHelpers.PrintCode("RandomNumberGenerator.Fill(key);");
        ConsoleHelpers.PrintCode("using (var writer = CyFileStream.CreateWrite(path, key))");

        using (var writer = CyFileStream.CreateWrite(tempFile2, key))
        {
            var payload = Encoding.UTF8.GetBytes("Encrypted with a random 256-bit key.");
            writer.Write(payload);
        }

        ConsoleHelpers.PrintSecure("File written with random AES-256 key.");

        using (var reader = CyFileStream.OpenRead(tempFile2, key))
        {
            var buffer = new byte[1024];
            var bytesRead = reader.Read(buffer);
            var plaintext = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            ConsoleHelpers.PrintRisk($"Decrypted: \"{plaintext}\"");
        }

        CryptographicOperations.ZeroMemory(key);
        Console.WriteLine();

        // --- CyStreamWriter / CyStreamReader for typed framing ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Part 3: Typed Stream Framing with CyStreamWriter/Reader");

        ConsoleHelpers.PrintNote("CyStreamWriter/Reader frame CyType values as [typeId:2][length:4][payload:N].");
        ConsoleHelpers.PrintNote("Values are transferred in their encrypted form — no plaintext is exposed in transit.");
        Console.WriteLine();

        var streamKey = new byte[32];
        RandomNumberGenerator.Fill(streamKey);

        // Write typed values to a memory stream
        ConsoleHelpers.PrintCode("var cyStream = CyStream.CreateWriter(memoryStream, key, keyId, chunkSize: 4096);");
        ConsoleHelpers.PrintCode("var writer = new CyStreamWriter(cyStream);");
        ConsoleHelpers.PrintCode("writer.WriteValue(cyInt);");
        ConsoleHelpers.PrintCode("writer.WriteValue(cyString);");
        ConsoleHelpers.PrintCode("writer.Complete();");

        using var memStream = new MemoryStream();
        var keyId = Guid.NewGuid();

        using var sourceInt = new CyInt(12345);
        using var sourceString = new CyString("encrypted-in-transit");

        using (var cyWriteStream = CyStream.CreateWriter(memStream, streamKey, keyId, chunkSize: 4096, leaveOpen: true))
        using (var typedWriter = new CyStreamWriter(cyWriteStream, leaveOpen: true))
        {
            typedWriter.WriteValue(sourceInt);
            typedWriter.WriteValue(sourceString);
            typedWriter.Complete();
        }

        ConsoleHelpers.PrintSecure($"Stream written: {memStream.Length} bytes (typed frames inside encrypted chunks)");
        ConsoleHelpers.PrintInfo($"CyInt value written (encrypted in memory, framed in stream)");
        ConsoleHelpers.PrintInfo($"CyString value written (encrypted in memory, framed in stream)");
        Console.WriteLine();

        // Read typed values back
        ConsoleHelpers.PrintCode("var cyReadStream = CyStream.CreateReader(memoryStream, key);");
        ConsoleHelpers.PrintCode("var reader = new CyStreamReader(cyReadStream);");
        ConsoleHelpers.PrintCode("foreach (var (typeId, payload) in reader.ReadAll()) { ... }");

        memStream.Position = 0;

        using (var cyReadStream = CyStream.CreateReader(memStream, streamKey, leaveOpen: true))
        using (var typedReader = new CyStreamReader(cyReadStream, leaveOpen: true))
        {
            var frameCount = 0;
            foreach (var (typeId, encryptedPayload) in typedReader.ReadAll())
            {
                frameCount++;
                ConsoleHelpers.PrintInfo($"Frame {frameCount}: typeId=0x{typeId:X4}, payload={encryptedPayload.Length} bytes");
            }
            ConsoleHelpers.PrintSecure($"Read {frameCount} typed frames from encrypted stream.");
        }

        CryptographicOperations.ZeroMemory(streamKey);
        Console.WriteLine();

        // --- Session key concept ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Concept: Session Key Negotiation");

        ConsoleHelpers.PrintNote("In production, the 256-bit stream key would be negotiated via:");
        ConsoleHelpers.PrintNote("  - TLS 1.3 handshake (for network streams via CyNetworkStream)");
        ConsoleHelpers.PrintNote("  - Post-quantum key exchange (ECDH + ML-KEM hybrid)");
        ConsoleHelpers.PrintNote("  - Pre-shared key (for file encryption or IPC via CyPipeStream)");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("// Network example (conceptual):");
        ConsoleHelpers.PrintCode("var server = new CyNetworkServer(port: 9443);");
        ConsoleHelpers.PrintCode("var client = new CyNetworkClient(\"localhost\", 9443);");
        ConsoleHelpers.PrintCode("// Session key is negotiated automatically during handshake");
        ConsoleHelpers.PrintCode("// All CyType values sent over the wire remain encrypted end-to-end");

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("Key takeaway: CyTypes.Streams encrypts data in chunked AES-256-GCM with integrity verification.");

        // Cleanup temp files
        try { File.Delete(tempFile); } catch { /* best effort */ }
        try { File.Delete(tempFile2); } catch { /* best effort */ }
    }
}
