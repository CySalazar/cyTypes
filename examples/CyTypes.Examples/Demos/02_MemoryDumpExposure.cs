using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class MemoryDumpExposure
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 2: Memory Dump Exposure - .NET vs CyTypes");
        ConsoleHelpers.PrintNote("Simulates what an attacker sees in a memory dump (/proc/pid/mem,");
        ConsoleHelpers.PrintNote("core dumps, cold-boot attacks, WinDbg, Volatility, etc.).");
        Console.WriteLine();

        // --- int vs CyInt ---
        ConsoleHelpers.PrintSubHeader("Integer: int vs CyInt");
        ConsoleHelpers.PrintNote(".NET int = 4 raw bytes on the managed heap, trivially readable.");

        int secret = 123_456_789;
        ConsoleHelpers.PrintCode("int secret = 123_456_789;");
        MemoryInspector.DumpValueMemory(ref secret, ".NET int   ");
        ConsoleHelpers.PrintRisk($"Plaintext visible: {secret} (bytes: 15 CD 5B 07)");

        using var cySecret = new CyInt(123_456_789);
        ConsoleHelpers.PrintCode("var cySecret = new CyInt(123_456_789);");
        MemoryInspector.DumpCyTypeInfo(cySecret, "CyInt      ");
        ConsoleHelpers.PrintSecure("Only encrypted ciphertext in memory — plaintext never stored");
        Console.WriteLine();

        // --- string vs CyString ---
        ConsoleHelpers.PrintSubHeader("String: string vs CyString");
        ConsoleHelpers.PrintNote(".NET strings are UTF-16 on the managed heap — every character is 2 bytes in cleartext.");

        string password = "MyS3cretP@ss!";
        ConsoleHelpers.PrintCode("string password = \"MyS3cretP@ss!\";");
        MemoryInspector.DumpStringMemory(password, ".NET string");
        ConsoleHelpers.PrintRisk($"UTF-16 plaintext visible: \"{password}\"");

        using var cyPassword = new CyString("MyS3cretP@ss!");
        ConsoleHelpers.PrintCode("var cyPassword = new CyString(\"MyS3cretP@ss!\");");
        MemoryInspector.DumpCyTypeInfo(cyPassword, "CyString   ");
        ConsoleHelpers.PrintSecure("Encrypted — no readable characters in memory");
        Console.WriteLine();

        // --- byte[] vs CyBytes ---
        ConsoleHelpers.PrintSubHeader("Byte Array: byte[] vs CyBytes");
        ConsoleHelpers.PrintNote("Cryptographic keys in byte[] sit in cleartext — one dump leaks the key material.");

        byte[] key = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04];
        ConsoleHelpers.PrintCode("byte[] key = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, ...];");
        MemoryInspector.DumpByteArrayMemory(key, ".NET byte[]");
        ConsoleHelpers.PrintRisk("Raw key material visible: DE AD BE EF CA FE BA BE ...");

        using var cyKey = new CyBytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04]);
        ConsoleHelpers.PrintCode("var cyKey = new CyBytes([0xDE, 0xAD, 0xBE, 0xEF, ...]);");
        MemoryInspector.DumpCyTypeInfo(cyKey, "CyBytes    ");
        ConsoleHelpers.PrintSecure("Key material encrypted with AES-256-GCM in pinned buffer");
        Console.WriteLine();

        // --- double vs CyDouble ---
        ConsoleHelpers.PrintSubHeader("Double: double vs CyDouble");
        ConsoleHelpers.PrintNote("Financial data in IEEE 754 doubles is directly readable from memory.");

        double balance = 99999.99;
        ConsoleHelpers.PrintCode("double balance = 99999.99;");
        MemoryInspector.DumpValueMemory(ref balance, ".NET double");
        ConsoleHelpers.PrintRisk($"IEEE 754 representation visible: {balance}");

        using var cyBalance = new CyDouble(99999.99);
        ConsoleHelpers.PrintCode("var cyBalance = new CyDouble(99999.99);");
        MemoryInspector.DumpCyTypeInfo(cyBalance, "CyDouble   ");
        ConsoleHelpers.PrintSecure("Balance encrypted — not recoverable from memory dump");
        Console.WriteLine();

        // --- Arithmetic results stay encrypted ---
        ConsoleHelpers.PrintSubHeader("Arithmetic Results Stay Encrypted in Memory");
        ConsoleHelpers.PrintNote("Even operation results remain encrypted — no plaintext intermediates in managed memory.");

        using var cyA = new CyInt(50_000);
        using var cyB = new CyInt(25_000);
        using var cySum = cyA + cyB;

        ConsoleHelpers.PrintCode("var cyA = new CyInt(50_000);");
        ConsoleHelpers.PrintCode("var cyB = new CyInt(25_000);");
        ConsoleHelpers.PrintCode("var cySum = cyA + cyB;");
        MemoryInspector.DumpCyTypeInfo(cySum, "CyInt(sum) ");
        ConsoleHelpers.PrintCode("cySum.IsCompromised");
        ConsoleHelpers.PrintSecure($"=> {cySum.IsCompromised}");
        Console.WriteLine();

        // --- Summary ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Summary: GC Copy Risk");
        ConsoleHelpers.PrintRisk(".NET GC may copy values across memory during compaction,");
        ConsoleHelpers.PrintRisk("leaving stale plaintext copies that cannot be zeroed.");
        ConsoleHelpers.PrintSecure("CyTypes uses pinned, locked buffers that prevent GC relocation.");
        ConsoleHelpers.PrintSecure("On Dispose(), all memory is cryptographically zeroed.");
        Console.WriteLine();

        ConsoleHelpers.PrintSubHeader("Comparison Table");
        ConsoleHelpers.PrintComparison("Memory contents", "Plaintext (readable)", "AES-256-GCM ciphertext");
        ConsoleHelpers.PrintComparison("GC relocation", "Yes (copies left)", "No (pinned buffers)");
        ConsoleHelpers.PrintComparison("Swap to disk", "Possible", "mlock prevents swap");
        ConsoleHelpers.PrintComparison("Zeroing on free", "Never", "Always (CryptographicOperations)");
        ConsoleHelpers.PrintComparison("Core dump exposure", "Full plaintext", "Only ciphertext");
    }
}
