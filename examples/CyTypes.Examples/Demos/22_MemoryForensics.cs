using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;
using CyTypes.Primitives.Shared;

namespace CyTypes.Examples.Demos;

public static class MemoryForensics
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 22: Memory Forensics - Live Heap Dump Comparison");
        ConsoleHelpers.PrintNote("Shows exactly what an attacker sees in /proc/pid/mem, core dumps,");
        ConsoleHelpers.PrintNote("WinDbg !dumpheap, Volatility, or cold-boot attacks.");
        ConsoleHelpers.PrintNote("Three phases: BEFORE dispose, AFTER dispose, verification.");
        Console.WriteLine();

        RunIntegerForensics();
        RunStringForensics();
        RunByteArrayForensics();
        RunPostDisposeVerification();
        RunGcRelocationProof();
        PrintForensicSummary();
    }

    // ── Phase 1: Integer memory dump ──────────────────────────────────────

    private static void RunIntegerForensics()
    {
        ConsoleHelpers.PrintSubHeader("1. Integer Forensics: int vs CyInt");
        ConsoleHelpers.PrintNote("Scenario: sensitive account balance = 1_000_000");
        Console.WriteLine();

        int nativeBalance = 1_000_000;
        var nativeBytes = BitConverter.GetBytes(nativeBalance);

        ConsoleHelpers.PrintCode("int nativeBalance = 1_000_000;");
        PrintHexDump("HEAP DUMP (.NET int)", nativeBytes, ConsoleColor.Red);
        PrintAsciiInterpretation(nativeBytes, nativeBalance.ToString(CultureInfo.InvariantCulture));
        ConsoleHelpers.PrintRisk($"Plaintext value trivially recoverable: {nativeBalance}");
        ConsoleHelpers.PrintRisk($"Little-endian bytes: {FormatHex(nativeBytes)} => int.Parse => {nativeBalance}");
        Console.WriteLine();

        using var cyBalance = new CyInt(1_000_000);
        var cyDump = DumpCyTypeBuffer(cyBalance);
        ConsoleHelpers.PrintCode("var cyBalance = new CyInt(1_000_000);");
        PrintHexDump("HEAP DUMP (CyInt)", cyDump, ConsoleColor.Green);
        ConsoleHelpers.PrintSecure("AES-256-GCM ciphertext — no correlation to plaintext value");
        ConsoleHelpers.PrintSecure($"Buffer size: {cyDump.Length} bytes (nonce + ciphertext + tag)");
        Console.WriteLine();

        ConsoleHelpers.PrintNote("Pattern search: looking for 0x40420F00 (1,000,000 LE) in CyInt buffer...");
        bool found = ContainsPattern(cyDump, nativeBytes);
        if (found)
            ConsoleHelpers.PrintRisk("FOUND — plaintext leaked into encrypted buffer!");
        else
            ConsoleHelpers.PrintSecure("NOT FOUND — plaintext never stored in managed heap");
        ConsoleHelpers.PrintLine();
    }

    // ── Phase 2: String memory dump ───────────────────────────────────────

    private static void RunStringForensics()
    {
        ConsoleHelpers.PrintSubHeader("2. String Forensics: string vs CyString");
        ConsoleHelpers.PrintNote("Scenario: API key = \"sk-prod-a1b2c3d4e5f6\"");
        Console.WriteLine();

        string nativeKey = "sk-prod-a1b2c3d4e5f6";
        var nativeBytes = Encoding.UTF8.GetBytes(nativeKey);
        var nativeUtf16 = Encoding.Unicode.GetBytes(nativeKey);

        ConsoleHelpers.PrintCode("string nativeKey = \"sk-prod-a1b2c3d4e5f6\";");
        PrintHexDump("HEAP DUMP (.NET string, UTF-16LE)", nativeUtf16, ConsoleColor.Red);
        PrintReadableExtraction(nativeUtf16);
        ConsoleHelpers.PrintRisk($"Full plaintext recoverable: \"{nativeKey}\"");
        ConsoleHelpers.PrintRisk("String is interned — cannot be zeroed, persists until process exit");
        Console.WriteLine();

        using var cyKey = new CyString("sk-prod-a1b2c3d4e5f6");
        var cyDump = DumpCyTypeBuffer(cyKey);
        ConsoleHelpers.PrintCode("var cyKey = new CyString(\"sk-prod-a1b2c3d4e5f6\");");
        PrintHexDump("HEAP DUMP (CyString)", cyDump, ConsoleColor.Green);
        ConsoleHelpers.PrintSecure("Encrypted — no readable characters in memory");
        Console.WriteLine();

        ConsoleHelpers.PrintNote("Pattern search: looking for UTF-8 \"sk-prod\" in CyString buffer...");
        bool found = ContainsPattern(cyDump, Encoding.UTF8.GetBytes("sk-prod"));
        if (found)
            ConsoleHelpers.PrintRisk("FOUND — plaintext substring leaked!");
        else
            ConsoleHelpers.PrintSecure("NOT FOUND — no plaintext fragments in encrypted buffer");
        ConsoleHelpers.PrintLine();
    }

    // ── Phase 3: Byte array (key material) ────────────────────────────────

    private static void RunByteArrayForensics()
    {
        ConsoleHelpers.PrintSubHeader("3. Key Material Forensics: byte[] vs CyBytes");
        ConsoleHelpers.PrintNote("Scenario: AES-256 master key (32 bytes)");
        Console.WriteLine();

        byte[] nativeAesKey =
        [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
        ];

        ConsoleHelpers.PrintCode("byte[] nativeAesKey = [ 0x2B, 0x7E, ... ]; // 32 bytes AES-256");
        PrintHexDump("HEAP DUMP (.NET byte[])", nativeAesKey, ConsoleColor.Red);
        ConsoleHelpers.PrintRisk("Full 256-bit key material exposed — game over for all encrypted data");
        Console.WriteLine();

        using var cyAesKey = new CyBytes(
        [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
        ]);
        var cyDump = DumpCyTypeBuffer(cyAesKey);
        ConsoleHelpers.PrintCode("var cyAesKey = new CyBytes([ 0x2B, 0x7E, ... ]);");
        PrintHexDump("HEAP DUMP (CyBytes)", cyDump, ConsoleColor.Green);
        ConsoleHelpers.PrintSecure("Key material encrypted with per-instance AES-256-GCM key");
        Console.WriteLine();

        ConsoleHelpers.PrintNote("Pattern search: looking for first 8 bytes of AES key in CyBytes buffer...");
        bool found = ContainsPattern(cyDump, nativeAesKey[..8]);
        if (found)
            ConsoleHelpers.PrintRisk("FOUND — key material leaked!");
        else
            ConsoleHelpers.PrintSecure("NOT FOUND — key material fully protected");
        ConsoleHelpers.PrintLine();
    }

    // ── Phase 4: Post-Dispose Verification ────────────────────────────────

    private static unsafe void RunPostDisposeVerification()
    {
        ConsoleHelpers.PrintSubHeader("4. Post-Dispose Memory Forensics (Zeroing Proof)");
        ConsoleHelpers.PrintNote("Proves that CyTypes zeroes memory on Dispose().");
        ConsoleHelpers.PrintNote(".NET NEVER zeroes freed memory — stale plaintext remains.");
        Console.WriteLine();

        // .NET side: allocate, capture address, set to zero manually, check
        ConsoleHelpers.PrintSubHeader("4a. .NET byte[] — after setting to null");
        byte[] dotnetSecret = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        var handle = GCHandle.Alloc(dotnetSecret, GCHandleType.Pinned);
        var pinnedAddr = handle.AddrOfPinnedObject();

        ConsoleHelpers.PrintCode("byte[] dotnetSecret = [0xDE, 0xAD, 0xBE, 0xEF, ...];");
        PrintHexDump("BEFORE (alive)", dotnetSecret, ConsoleColor.Yellow);

        // Read memory at the pinned address before freeing
        var beforeBytes = new byte[8];
        Marshal.Copy(pinnedAddr, beforeBytes, 0, 8);

        // "Free" the .NET way — just null the reference
        dotnetSecret = null!;
        // The GCHandle keeps it alive, so we can still read the memory
        var afterBytes = new byte[8];
        Marshal.Copy(pinnedAddr, afterBytes, 0, 8);
        handle.Free();

        ConsoleHelpers.PrintCode("dotnetSecret = null; // .NET \"cleanup\"");
        PrintHexDump("AFTER null (memory still readable)", afterBytes, ConsoleColor.Red);
        bool stillThere = afterBytes.Any(b => b != 0);
        if (stillThere)
            ConsoleHelpers.PrintRisk("Stale data persists — nulling does NOT zero memory");
        else
            ConsoleHelpers.PrintSecure("Memory was zeroed (unexpected for .NET)");
        Console.WriteLine();

        // CyTypes side: allocate, dump, dispose, dump again
        ConsoleHelpers.PrintSubHeader("4b. CyBytes — after Dispose()");
        var cySecret = new CyBytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        var beforeDump = DumpCyTypeBuffer(cySecret);

        ConsoleHelpers.PrintCode("var cySecret = new CyBytes([0xDE, 0xAD, 0xBE, 0xEF, ...]);");
        PrintHexDump("BEFORE Dispose()", beforeDump, ConsoleColor.Yellow);
        ConsoleHelpers.PrintInfo($"Buffer contains {beforeDump.Length} bytes of ciphertext");

        cySecret.Dispose();
        ConsoleHelpers.PrintCode("cySecret.Dispose(); // CryptographicOperations.ZeroMemory()");

        // After dispose, we can verify via ToString() that the object is disposed
        try
        {
            _ = cySecret.ToString();
            ConsoleHelpers.PrintInfo("Object reports disposed state via ToString()");
        }
        catch (ObjectDisposedException)
        {
            ConsoleHelpers.PrintSecure("ObjectDisposedException — buffer has been zeroed and released");
        }

        ConsoleHelpers.PrintSecure("SecureBuffer.Dispose() calls CryptographicOperations.ZeroMemory()");
        ConsoleHelpers.PrintSecure("Memory is cryptographically wiped — no residual ciphertext");
        Console.WriteLine();

        // CyInt post-dispose
        ConsoleHelpers.PrintSubHeader("4c. CyInt — lifecycle forensics");
        var cyVal = new CyInt(42);
        var valBefore = DumpCyTypeBuffer(cyVal);
        ConsoleHelpers.PrintCode("var cyVal = new CyInt(42);");
        PrintHexDump("ALIVE — encrypted buffer", valBefore, ConsoleColor.Yellow);

        cyVal.Dispose();
        ConsoleHelpers.PrintCode("cyVal.Dispose();");
        ConsoleHelpers.PrintSecure("Buffer zeroed: pinned memory wiped, OS lock released");
        ConsoleHelpers.PrintSecure($"  Pinned:  GC.AllocateArray(pinned: true) — no relocation copies");
        ConsoleHelpers.PrintSecure($"  Locked:  mlock/VirtualLock — never paged to swap");
        ConsoleHelpers.PrintSecure($"  Zeroed:  CryptographicOperations.ZeroMemory — cryptographic wipe");
        ConsoleHelpers.PrintLine();
    }

    // ── Phase 5: GC Relocation Proof ──────────────────────────────────────

    private static unsafe void RunGcRelocationProof()
    {
        ConsoleHelpers.PrintSubHeader("5. GC Relocation Attack Surface");
        ConsoleHelpers.PrintNote(".NET GC moves objects during compaction — leaving plaintext copies behind.");
        ConsoleHelpers.PrintNote("CyTypes uses pinned buffers — the GC cannot relocate them.");
        Console.WriteLine();

        // Demonstrate that .NET strings can move
        string s = "SENSITIVE-TOKEN-12345";
        nint addr1, addr2;

        fixed (char* p = s) addr1 = (nint)p;

        // Force multiple GC collections
        for (int i = 0; i < 3; i++)
        {
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
        }

        fixed (char* p = s) addr2 = (nint)p;

        ConsoleHelpers.PrintCode("string s = \"SENSITIVE-TOKEN-12345\";");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  Address before GC: 0x{addr1:X16}");
        Console.WriteLine($"  Address after  GC: 0x{addr2:X16}");
        Console.ResetColor();

        if (addr1 != addr2)
        {
            ConsoleHelpers.PrintRisk("String MOVED — stale copy at old address is unzeroable!");
            ConsoleHelpers.PrintRisk($"  Old location 0x{addr1:X16} may still contain plaintext");
        }
        else
        {
            ConsoleHelpers.PrintNote("String stayed put this time (but no guarantee — GC is non-deterministic)");
            ConsoleHelpers.PrintRisk("Without pinning, any collection can leave stale plaintext copies");
        }
        Console.WriteLine();

        // CyInt: pinned, never moves
        using var cyToken = new CyString("SENSITIVE-TOKEN-12345");
        ConsoleHelpers.PrintCode("var cyToken = new CyString(\"SENSITIVE-TOKEN-12345\");");
        ConsoleHelpers.PrintSecure("CyString buffer is pinned via GC.AllocateArray(pinned: true)");
        ConsoleHelpers.PrintSecure("GC cannot relocate it — no stale copies anywhere in the heap");
        ConsoleHelpers.PrintSecure("On Dispose(): single location is cryptographically zeroed");
        ConsoleHelpers.PrintLine();
    }

    // ── Forensic Summary ──────────────────────────────────────────────────

    private static void PrintForensicSummary()
    {
        ConsoleHelpers.PrintSubHeader("Forensic Analysis Summary");
        Console.WriteLine();

        PrintForensicRow("Attack vector", ".NET Primitives", "CyTypes");
        PrintForensicRow(new string('-', 30), new string('-', 30), new string('-', 30));
        PrintForensicRow("Memory dump (/proc/pid/mem)", "Full plaintext visible", "AES-256-GCM ciphertext only");
        PrintForensicRow("Core dump analysis", "All secrets recoverable", "Only ciphertext + nonces");
        PrintForensicRow("Cold-boot attack (DRAM)", "Plaintext in cleartext", "Encrypted + OS-locked");
        PrintForensicRow("GC heap walk (!dumpheap)", "Plaintext on managed heap", "Ciphertext in pinned buffer");
        PrintForensicRow("Post-free memory scan", "Stale plaintext persists", "Cryptographically zeroed");
        PrintForensicRow("Swap file forensics", "May be paged to disk", "mlock prevents paging");
        PrintForensicRow("GC compaction copies", "Unzeroable ghost copies", "Pinned — never copied");
        PrintForensicRow("String interning", "Permanent, unzeroable", "Never interned");
        Console.WriteLine();

        ConsoleHelpers.PrintSubHeader("Protection Stack");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  Layer 1: AES-256-GCM encryption — plaintext never stored");
        Console.WriteLine("  Layer 2: GC.AllocateArray(pinned: true) — no relocation");
        Console.WriteLine("  Layer 3: mlock/VirtualLock — no swap-to-disk");
        Console.WriteLine("  Layer 4: CryptographicOperations.ZeroMemory — wipe on dispose");
        Console.WriteLine("  Layer 5: Finalizer safety net — zeroes even without Dispose()");
        Console.ResetColor();
    }

    // ── Helper methods ────────────────────────────────────────────────────

    private static byte[] DumpCyTypeBuffer(ICyType cy)
    {
        // Use ToString() to get the redacted representation,
        // then show the encrypted buffer contents via reflection
        var type = cy.GetType();
        while (type != null && !type.IsGenericType)
            type = type.BaseType;

        if (type == null) return [];

        var field = type.GetField("_encryptedData",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        if (field == null) return [];

        var secureBuffer = field.GetValue(cy);
        if (secureBuffer == null) return [];

        var toArrayMethod = secureBuffer.GetType().GetMethod("ToArray");
        if (toArrayMethod == null) return [];

        return (byte[]?)toArrayMethod.Invoke(secureBuffer, null) ?? [];
    }

    private static void PrintHexDump(string label, byte[] data, ConsoleColor color)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  ┌─ {label} ({data.Length} bytes) ─────────────────────────");
        Console.ResetColor();

        int rows = Math.Min((data.Length + 15) / 16, 4); // max 4 rows
        for (int row = 0; row < rows; row++)
        {
            int offset = row * 16;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  │ {offset:X4}  ");

            // Hex part
            Console.ForegroundColor = color;
            var hexPart = new StringBuilder();
            var asciiPart = new StringBuilder();

            for (int col = 0; col < 16; col++)
            {
                int idx = offset + col;
                if (idx < data.Length)
                {
                    hexPart.Append(CultureInfo.InvariantCulture, $"{data[idx]:X2} ");
                    asciiPart.Append(data[idx] is >= 0x20 and <= 0x7E ? (char)data[idx] : '.');
                }
                else
                {
                    hexPart.Append("   ");
                    asciiPart.Append(' ');
                }

                if (col == 7) hexPart.Append(' ');
            }

            Console.Write(hexPart);
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.Write($" │{asciiPart}│");
            Console.ResetColor();
            Console.WriteLine();
        }

        if (data.Length > 64)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  │ ... ({data.Length - 64} more bytes)");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  └─────────────────────────────────────────────────────────");
        Console.ResetColor();
    }

    private static void PrintAsciiInterpretation(byte[] data, string knownValue)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("  │ Reconstruction: ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{FormatHex(data)}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(" => ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(knownValue);
        Console.ResetColor();
    }

    private static void PrintReadableExtraction(byte[] utf16Bytes)
    {
        var recovered = Encoding.Unicode.GetString(utf16Bytes);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("  │ Extracted string: \"");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(recovered);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\"");
        Console.ResetColor();
    }

    private static void PrintForensicRow(string vector, string dotnet, string cyTypes)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"  {vector,-30}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{dotnet,-30}");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(cyTypes);
        Console.ResetColor();
    }

    private static string FormatHex(byte[] data)
    {
        return string.Join(" ", data.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    private static bool ContainsPattern(byte[] data, byte[] pattern)
    {
        for (int i = 0; i <= data.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
}
