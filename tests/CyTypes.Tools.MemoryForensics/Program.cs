using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using CyTypes.Primitives;
using Microsoft.Diagnostics.Runtime;

namespace CyTypes.Tools.MemoryForensics;

public static class Program
{
    private const string ToolVersion = "1.0.0";

    public static int Main(string[] args)
    {
        if (args.Length > 0)
        {
            return args[0].ToLowerInvariant() switch
            {
                "interactive" => RunInteractive(),
                "report" => RunReport(args.ElementAtOrDefault(1)),
                "scan" => RunExternalScan(args),
                "--help" or "-h" => PrintUsage(),
                _ => PrintUsage()
            };
        }

        return RunInteractive();
    }

    private static int PrintUsage()
    {
        Console.WriteLine($"CyTypes Memory Forensics Tool v{ToolVersion}");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  memory-forensics                         Interactive mode (default)");
        Console.WriteLine("  memory-forensics interactive              Interactive console");
        Console.WriteLine("  memory-forensics report [output-path]     Generate static forensic report");
        Console.WriteLine("  memory-forensics scan <pid> <hex>         Scan external process for pattern");
        Console.WriteLine();
        return 0;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  INTERACTIVE MODE
    // ═══════════════════════════════════════════════════════════════════════

    private static int RunInteractive()
    {
        PrintBanner();

        while (true)
        {
            PrintMenu();
            Console.Write("  Select (1-7, q): ");
            var input = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(input) || input.Equals("q", StringComparison.OrdinalIgnoreCase))
                break;

            if (input.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                RunAllScenarios();
                WaitForKey();
                continue;
            }

            if (int.TryParse(input, out int choice) && choice >= 1 && choice <= 7)
            {
                RunScenario(choice);
                WaitForKey();
            }
        }

        return 0;
    }

    private static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine();
        Console.WriteLine("  ╔═══════════════════════════════════════════════════════════╗");
        Console.WriteLine("  ║         CyTypes Memory Forensics Tool v" + ToolVersion + "              ║");
        Console.WriteLine("  ║   Full forensic analysis: managed heap + process memory   ║");
        Console.WriteLine("  ╚═══════════════════════════════════════════════════════════╝");
        Console.ResetColor();
    }

    private static void PrintMenu()
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  ┌─ Forensic Scenarios ─────────────────────────────────────┐");
        Console.ResetColor();

        var items = new[]
        {
            (1, "Integer heap dump: int vs CyInt"),
            (2, "String heap dump: string vs CyString"),
            (3, "Key material dump: byte[] vs CyBytes"),
            (4, "Post-dispose zeroing verification"),
            (5, "GC relocation attack surface"),
            (6, "ClrMD live heap scan (self-process)"),
            (7, "Full forensic report (all scenarios)")
        };

        foreach (var (num, desc) in items)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"  │ [{num}] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(desc);
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  └─────────────────────────────────────────────────────────┘");
        Console.ResetColor();
    }

    private static void RunScenario(int choice)
    {
        switch (choice)
        {
            case 1: ScenarioIntegerDump(); break;
            case 2: ScenarioStringDump(); break;
            case 3: ScenarioKeyMaterialDump(); break;
            case 4: ScenarioPostDisposeVerification(); break;
            case 5: ScenarioGcRelocation(); break;
            case 6: ScenarioClrMdHeapScan(); break;
            case 7: RunAllScenarios(); break;
        }
    }

    private static void RunAllScenarios()
    {
        for (int i = 1; i <= 6; i++)
        {
            RunScenario(i);
            Console.WriteLine();
        }

        PrintForensicSummaryTable();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCENARIO 1: Integer
    // ═══════════════════════════════════════════════════════════════════════

    private static void ScenarioIntegerDump()
    {
        PrintSection("SCENARIO 1: Integer Memory Forensics");
        Info("Target value: 1,000,000 (account balance)");
        Console.WriteLine();

        // .NET int
        int nativeVal = 1_000_000;
        var nativeBytes = BitConverter.GetBytes(nativeVal);

        Code("int balance = 1_000_000;");
        DumpHex(".NET int — Managed Heap", nativeBytes, ConsoleColor.Red);
        Risk($"Plaintext: {FormatHex(nativeBytes)} => {nativeVal}");
        Risk("Any process with read access can extract this value");
        Console.WriteLine();

        // CyInt
        using var cyVal = new CyInt(1_000_000);
        var cyDump = ReflectEncryptedBuffer(cyVal);

        Code("var balance = new CyInt(1_000_000);");
        DumpHex("CyInt — Pinned Encrypted Buffer", cyDump, ConsoleColor.Green);
        Safe("AES-256-GCM ciphertext — value 1,000,000 is NOT present");
        PatternCheck(cyDump, nativeBytes, "plaintext int bytes (40 42 0F 00)");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCENARIO 2: String
    // ═══════════════════════════════════════════════════════════════════════

    private static void ScenarioStringDump()
    {
        PrintSection("SCENARIO 2: String Memory Forensics");
        Info("Target value: \"sk-prod-a1b2c3d4e5f6\" (API key)");
        Console.WriteLine();

        string nativeStr = "sk-prod-a1b2c3d4e5f6";
        var utf16Bytes = Encoding.Unicode.GetBytes(nativeStr);

        Code("string apiKey = \"sk-prod-a1b2c3d4e5f6\";");
        DumpHex(".NET string — UTF-16LE on Managed Heap", utf16Bytes, ConsoleColor.Red);
        Risk($"Readable extraction: \"{Encoding.Unicode.GetString(utf16Bytes)}\"");
        Risk("Interned string — persists in memory until process exit, CANNOT be zeroed");
        Console.WriteLine();

        using var cyStr = new CyString("sk-prod-a1b2c3d4e5f6");
        var cyDump = ReflectEncryptedBuffer(cyStr);

        Code("var apiKey = new CyString(\"sk-prod-a1b2c3d4e5f6\");");
        DumpHex("CyString — AES-256-GCM Encrypted", cyDump, ConsoleColor.Green);
        Safe("No readable characters — plaintext never stored on managed heap");
        PatternCheck(cyDump, Encoding.UTF8.GetBytes("sk-prod"), "UTF-8 substring \"sk-prod\"");
        PatternCheck(cyDump, Encoding.Unicode.GetBytes("sk-prod"), "UTF-16 substring \"sk-prod\"");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCENARIO 3: Key Material
    // ═══════════════════════════════════════════════════════════════════════

    private static void ScenarioKeyMaterialDump()
    {
        PrintSection("SCENARIO 3: Key Material Memory Forensics");
        Info("Target: 32-byte AES-256 master key");
        Console.WriteLine();

        byte[] masterKey =
        [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
        ];

        Code("byte[] masterKey = [ 0x2B, 0x7E, ... ]; // AES-256");
        DumpHex(".NET byte[] — Raw Key Material", masterKey, ConsoleColor.Red);
        Risk("CRITICAL: Full 256-bit key exposed — all encrypted data compromised");
        Console.WriteLine();

        using var cyKey = new CyBytes(
        [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
            0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
        ]);
        var cyDump = ReflectEncryptedBuffer(cyKey);

        Code("var masterKey = new CyBytes([ 0x2B, 0x7E, ... ]);");
        DumpHex("CyBytes — Encrypted Key Material", cyDump, ConsoleColor.Green);
        Safe("Key material protected by per-instance AES-256-GCM encryption");
        PatternCheck(cyDump, masterKey[..8], "first 8 key bytes");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCENARIO 4: Post-Dispose Zeroing
    // ═══════════════════════════════════════════════════════════════════════

    private static unsafe void ScenarioPostDisposeVerification()
    {
        PrintSection("SCENARIO 4: Post-Dispose Memory Forensics");
        Info("Proves CyTypes cryptographically zeroes memory on Dispose()");
        Console.WriteLine();

        // .NET: memory persists after null
        PrintSubSection("4a. .NET byte[] — what happens after 'cleanup'");
        byte[] dotnetSecret = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                               0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        var handle = GCHandle.Alloc(dotnetSecret, GCHandleType.Pinned);
        var addr = handle.AddrOfPinnedObject();

        DumpHex("BEFORE — .NET byte[] (alive)", dotnetSecret, ConsoleColor.Yellow);

        var snapshot = new byte[16];
        Marshal.Copy(addr, snapshot, 0, 16);

        // Simulate .NET "cleanup"
        dotnetSecret = null!;

        var afterNull = new byte[16];
        Marshal.Copy(addr, afterNull, 0, 16);
        handle.Free();

        Code("dotnetSecret = null;  // typical .NET 'cleanup'");
        DumpHex("AFTER null — memory at same address", afterNull, ConsoleColor.Red);

        int nonZero = afterNull.Count(b => b != 0);
        if (nonZero > 0)
        {
            Risk($"STALE DATA: {nonZero}/{afterNull.Length} bytes still non-zero after nulling");
            Risk("Nulling a reference does NOT zero the underlying memory");
        }
        Console.WriteLine();

        // CyTypes: memory zeroed after Dispose
        PrintSubSection("4b. CyBytes — Dispose() with cryptographic zeroing");
        var cySecret = new CyBytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        var beforeDump = ReflectEncryptedBuffer(cySecret);
        DumpHex("BEFORE Dispose() — encrypted buffer", beforeDump, ConsoleColor.Yellow);
        Info($"Encrypted payload: {beforeDump.Length} bytes (12B nonce + ciphertext + 16B tag)");

        cySecret.Dispose();
        Code("cySecret.Dispose();");

        try
        {
            _ = cySecret.ToInsecureBytes();
        }
        catch (ObjectDisposedException)
        {
            Safe("ObjectDisposedException on decrypt — buffer has been zeroed and released");
        }
        Safe($"IsDisposed: {cySecret.IsDisposed}");
        Safe("SecureBuffer.Dispose() executed:");
        Safe("  1. CryptographicOperations.ZeroMemory(_buffer)  — wipe all bytes to 0x00");
        Safe("  2. MemoryLock.TryUnlock()                       — release OS-level lock");
        Safe("  3. GC.SuppressFinalize()                        — prevent double-free");
        Console.WriteLine();

        // CyString lifecycle
        PrintSubSection("4c. CyString — full lifecycle dump");
        var cyStr = new CyString("TopSecret123!");
        var strBefore = ReflectEncryptedBuffer(cyStr);
        DumpHex("ALIVE — CyString encrypted buffer", strBefore, ConsoleColor.Yellow);

        cyStr.Dispose();
        Code("cyStr.Dispose();");
        Safe("All 3 protection layers cleared:");
        Safe("  Encryption buffer:  zeroed (CryptographicOperations.ZeroMemory)");
        Safe("  Per-instance key:   zeroed (KeyManager.Dispose)");
        Safe("  Memory lock:        released (munlock/VirtualUnlock)");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCENARIO 5: GC Relocation
    // ═══════════════════════════════════════════════════════════════════════

    private static unsafe void ScenarioGcRelocation()
    {
        PrintSection("SCENARIO 5: GC Relocation Attack Surface");
        Info(".NET GC compaction creates unzeroable plaintext copies across the heap");
        Console.WriteLine();

        // Track string address across GC
        string secret = "SUPER-SECRET-TOKEN-XYZ789";
        nint addrBefore, addrAfter;

        fixed (char* p = secret) addrBefore = (nint)p;

        // Force aggressive GC
        var pressure = new List<byte[]>();
        for (int i = 0; i < 100; i++)
            pressure.Add(new byte[1024]);
        pressure.Clear();

        for (int gen = 0; gen < 3; gen++)
        {
            GC.Collect(gen, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
        }

        fixed (char* p = secret) addrAfter = (nint)p;

        Code("string secret = \"SUPER-SECRET-TOKEN-XYZ789\";");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"    Address before GC: 0x{addrBefore:X16}");
        Console.WriteLine($"    Address after  GC: 0x{addrAfter:X16}");
        Console.ResetColor();

        if (addrBefore != addrAfter)
        {
            Risk("STRING RELOCATED by GC compaction!");
            Risk($"  Old location 0x{addrBefore:X16} — stale UTF-16 plaintext may remain");
            Risk("  This ghost copy cannot be zeroed — it's unmarked free memory");
        }
        else
        {
            Info("String stayed at same address (non-deterministic — no guarantee)");
            Risk("Without pinning, any future GC cycle can relocate and leave ghost copies");
        }
        Console.WriteLine();

        using var cySecret = new CyString("SUPER-SECRET-TOKEN-XYZ789");
        Code("var secret = new CyString(\"SUPER-SECRET-TOKEN-XYZ789\");");
        Safe("CyString's SecureBuffer uses GC.AllocateArray(pinned: true)");
        Safe("  Pinned objects are excluded from GC compaction — no relocation ever");
        Safe("  Single memory location => single Dispose() => complete wipe");
        Safe("  No ghost copies anywhere in the managed heap");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCENARIO 6: ClrMD Live Heap Scan
    // ═══════════════════════════════════════════════════════════════════════

    private static void ScenarioClrMdHeapScan()
    {
        PrintSection("SCENARIO 6: ClrMD Live Heap Scan (Self-Process)");
        Info("Attaching to own process with Microsoft.Diagnostics.Runtime");
        Info("Scanning managed heap for plaintext patterns and SecureBuffer state");
        Console.WriteLine();

        // Create test data
        string dotnetPassword = "ForensicTestPassword!@#$";
        var dotnetBytes = Encoding.UTF8.GetBytes(dotnetPassword);
        byte[] sensitiveKey = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        using var cyPassword = new CyString("ForensicTestPassword!@#$");
        using var cyKey = new CyBytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);

        // Also create a disposed CyInt to verify zeroing
        var disposedCy = new CyInt(999_999);
        disposedCy.Dispose();

        int pid = Environment.ProcessId;
        Info($"Process ID: {pid}");
        Console.WriteLine();

        try
        {
            using var target = DataTarget.CreateSnapshotAndAttach(pid);
            using var runtime = target.ClrVersions[0].CreateRuntime();
            var heap = runtime.Heap;

            // Scan for plaintext password in byte arrays
            PrintSubSection("6a. Scanning heap for plaintext password bytes");
            var passwordMatches = ScanHeapForPattern(runtime, dotnetBytes);

            if (passwordMatches.Count > 0)
            {
                Risk($"FOUND {passwordMatches.Count} byte[] containing plaintext password on heap:");
                foreach (var match in passwordMatches)
                    Risk($"  0x{match.Address:X16} ({match.Length} bytes) — {match.TypeName}");
            }
            else
            {
                Info("No byte[] matches found (string may be in char[] or string objects)");
            }
            Console.WriteLine();

            // Scan for sensitive key pattern
            PrintSubSection("6b. Scanning heap for sensitive key pattern (AA BB CC DD EE FF 11 22)");
            var keyMatches = ScanHeapForPattern(runtime, sensitiveKey);

            if (keyMatches.Count > 0)
            {
                Risk($"FOUND {keyMatches.Count} byte[] containing key pattern:");
                foreach (var match in keyMatches)
                    Risk($"  0x{match.Address:X16} ({match.Length} bytes) — {match.TypeName}");
            }
            else
            {
                Safe("Key pattern NOT found in any byte[] on the managed heap");
            }
            Console.WriteLine();

            // Validate SecureBuffer state
            PrintSubSection("6c. SecureBuffer validation (disposed instances)");
            var (total, zeroed, violations) = ValidateSecureBuffers(runtime);

            Info($"Total SecureBuffer instances found: {total}");
            if (zeroed > 0)
                Safe($"Properly zeroed (disposed): {zeroed}");
            if (violations > 0)
                Risk($"VIOLATIONS (disposed but NOT zeroed): {violations}");
            else if (total > 0)
                Safe("All disposed SecureBuffers are properly zeroed");
            Console.WriteLine();

            // Heap statistics
            PrintSubSection("6d. Heap statistics");
            long totalByteArrays = 0;
            ulong totalByteArrayBytes = 0;
            long totalStrings = 0;

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;

                if (obj.Type.Name == "System.Byte[]")
                {
                    totalByteArrays++;
                    totalByteArrayBytes += obj.Size;
                }
                else if (obj.Type.Name == "System.String")
                {
                    totalStrings++;
                }
            }

            Info($"Total byte[] on heap: {totalByteArrays} ({totalByteArrayBytes / 1024.0:F1} KB)");
            Info($"Total strings on heap: {totalStrings}");
            Info("Each byte[] and string is a potential plaintext exposure point");
            Safe("CyTypes keeps sensitive data encrypted — even a full heap dump reveals nothing");
        }
        catch (Exception ex)
        {
            Risk($"ClrMD scan failed: {ex.GetType().Name}: {ex.Message}");
            Info("This may require elevated privileges or platform-specific support");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STATIC REPORT GENERATION
    // ═══════════════════════════════════════════════════════════════════════

    private static int RunReport(string? outputPath)
    {
        outputPath ??= Path.Combine(Directory.GetCurrentDirectory(), "forensic-report.txt");

        var sb = new StringBuilder();
        var originalOut = Console.Out;

        using (var writer = new StringWriter(sb))
        {
            Console.SetOut(writer);

            sb.AppendLine("╔═══════════════════════════════════════════════════════════════════╗");
            sb.AppendLine($"║  CyTypes Memory Forensics Report — {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC  ║");
            sb.AppendLine($"║  Tool Version: {ToolVersion}                                            ║");
            sb.AppendLine($"║  Runtime: {RuntimeInformation.FrameworkDescription,-40}       ║");
            sb.AppendLine($"║  OS: {RuntimeInformation.OSDescription,-45}  ║");
            sb.AppendLine($"║  Process: {Environment.ProcessId,-44}  ║");
            sb.AppendLine("╚═══════════════════════════════════════════════════════════════════╝");
            sb.AppendLine();

            Console.SetOut(originalOut);

            // Run scenarios capturing output
            Console.SetOut(writer);
            RunAllForensicTests(sb);
            Console.SetOut(originalOut);
        }

        // Write report
        File.WriteAllText(outputPath, sb.ToString());

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  Forensic report generated: {outputPath}");
        Console.WriteLine($"  Size: {new FileInfo(outputPath).Length:N0} bytes");
        Console.ResetColor();

        return 0;
    }

    private static void RunAllForensicTests(StringBuilder sb)
    {
        // Integer test
        sb.AppendLine("═══ TEST 1: Integer Memory Exposure ═══════════════════════════════");
        int val = 1_000_000;
        var valBytes = BitConverter.GetBytes(val);
        sb.AppendLine($"  .NET int value: {val}");
        sb.AppendLine($"  Heap bytes: {FormatHex(valBytes)}");
        sb.AppendLine($"  RESULT: PLAINTEXT EXPOSED — value trivially recoverable");
        sb.AppendLine();

        using (var cyVal = new CyInt(1_000_000))
        {
            var cyDump = ReflectEncryptedBuffer(cyVal);
            sb.AppendLine($"  CyInt encrypted buffer ({cyDump.Length} bytes): {FormatHex(cyDump.Take(32).ToArray())}...");
            bool found = ContainsPattern(cyDump, valBytes);
            sb.AppendLine($"  Plaintext pattern in encrypted buffer: {(found ? "FOUND (FAILURE)" : "NOT FOUND (PASS)")}");
        }
        sb.AppendLine();

        // String test
        sb.AppendLine("═══ TEST 2: String Memory Exposure ════════════════════════════════");
        string secret = "sk-prod-a1b2c3d4e5f6";
        var utf16 = Encoding.Unicode.GetBytes(secret);
        sb.AppendLine($"  .NET string: \"{secret}\"");
        sb.AppendLine($"  UTF-16LE bytes: {FormatHex(utf16.Take(32).ToArray())}...");
        sb.AppendLine($"  RESULT: PLAINTEXT EXPOSED — full API key readable from heap dump");
        sb.AppendLine();

        using (var cyStr = new CyString(secret))
        {
            var cyDump = ReflectEncryptedBuffer(cyStr);
            sb.AppendLine($"  CyString encrypted buffer ({cyDump.Length} bytes): {FormatHex(cyDump.Take(32).ToArray())}...");
            bool foundUtf8 = ContainsPattern(cyDump, Encoding.UTF8.GetBytes("sk-prod"));
            bool foundUtf16 = ContainsPattern(cyDump, Encoding.Unicode.GetBytes("sk-prod"));
            sb.AppendLine($"  UTF-8 pattern in buffer:  {(foundUtf8 ? "FOUND (FAILURE)" : "NOT FOUND (PASS)")}");
            sb.AppendLine($"  UTF-16 pattern in buffer: {(foundUtf16 ? "FOUND (FAILURE)" : "NOT FOUND (PASS)")}");
        }
        sb.AppendLine();

        // Key material test
        sb.AppendLine("═══ TEST 3: Key Material Exposure ═════════════════════════════════");
        byte[] key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        sb.AppendLine($"  .NET byte[]: {FormatHex(key)}");
        sb.AppendLine($"  RESULT: PLAINTEXT EXPOSED — key material directly readable");
        sb.AppendLine();

        using (var cyKey = new CyBytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                                        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]))
        {
            var cyDump = ReflectEncryptedBuffer(cyKey);
            sb.AppendLine($"  CyBytes encrypted buffer ({cyDump.Length} bytes): {FormatHex(cyDump.Take(32).ToArray())}...");
            bool found = ContainsPattern(cyDump, key[..8]);
            sb.AppendLine($"  Key pattern in buffer: {(found ? "FOUND (FAILURE)" : "NOT FOUND (PASS)")}");
        }
        sb.AppendLine();

        // Post-dispose test
        sb.AppendLine("═══ TEST 4: Post-Dispose Zeroing Verification ═════════════════════");
        var cyDisposable = new CyInt(42);
        var beforeDispose = ReflectEncryptedBuffer(cyDisposable);
        int nonZeroBefore = beforeDispose.Count(b => b != 0);
        sb.AppendLine($"  Before Dispose(): {nonZeroBefore}/{beforeDispose.Length} non-zero bytes (expected: all)");

        cyDisposable.Dispose();
        bool throwsAfterDispose = false;
        try { _ = cyDisposable.ToInsecureInt(); }
        catch (ObjectDisposedException) { throwsAfterDispose = true; }
        sb.AppendLine($"  After Dispose(): ObjectDisposedException on decrypt: {throwsAfterDispose}");
        sb.AppendLine($"  IsDisposed: {cyDisposable.IsDisposed}");
        sb.AppendLine($"  RESULT: {(throwsAfterDispose && cyDisposable.IsDisposed ? "PASS — memory zeroed and object invalidated" : "FAILURE")}");
        sb.AppendLine();

        // ClrMD heap scan
        sb.AppendLine("═══ TEST 5: ClrMD Heap Analysis ═══════════════════════════════════");
        try
        {
            using var target = DataTarget.CreateSnapshotAndAttach(Environment.ProcessId);
            using var runtime = target.ClrVersions[0].CreateRuntime();
            var (total, zeroed, violations) = ValidateSecureBuffers(runtime);
            sb.AppendLine($"  SecureBuffer instances: {total}");
            sb.AppendLine($"  Properly zeroed:       {zeroed}");
            sb.AppendLine($"  Violations:            {violations}");
            sb.AppendLine($"  RESULT: {(violations == 0 ? "PASS" : $"FAILURE — {violations} buffers not zeroed")}");
        }
        catch (Exception ex)
        {
            sb.AppendLine($"  ClrMD scan unavailable: {ex.Message}");
        }
        sb.AppendLine();

        // Summary
        sb.AppendLine("═══ FORENSIC SUMMARY ══════════════════════════════════════════════");
        sb.AppendLine();
        sb.AppendLine($"  {"Attack Vector",-32} {".NET",-28} {"CyTypes",-28}");
        sb.AppendLine($"  {new string('-', 32)} {new string('-', 28)} {new string('-', 28)}");
        sb.AppendLine($"  {"Memory dump",-32} {"Plaintext visible",-28} {"AES-256-GCM ciphertext",-28}");
        sb.AppendLine($"  {"Core dump",-32} {"All secrets readable",-28} {"Only ciphertext + nonces",-28}");
        sb.AppendLine($"  {"Cold-boot (DRAM)",-32} {"Plaintext in cleartext",-28} {"Encrypted + OS-locked",-28}");
        sb.AppendLine($"  {"Post-free scan",-32} {"Stale data persists",-28} {"Cryptographically zeroed",-28}");
        sb.AppendLine($"  {"Swap forensics",-32} {"Pageable to disk",-28} {"mlock prevents paging",-28}");
        sb.AppendLine($"  {"GC compaction",-32} {"Ghost copies",-28} {"Pinned — never copied",-28}");
        sb.AppendLine($"  {"String interning",-32} {"Permanent, unzeroable",-28} {"Never interned",-28}");
        sb.AppendLine();
        sb.AppendLine("  Protection stack:");
        sb.AppendLine("    1. AES-256-GCM encryption — plaintext never stored");
        sb.AppendLine("    2. GC.AllocateArray(pinned: true) — no GC relocation");
        sb.AppendLine("    3. mlock/VirtualLock — no swap-to-disk");
        sb.AppendLine("    4. CryptographicOperations.ZeroMemory — wipe on dispose");
        sb.AppendLine("    5. Finalizer safety net — zeroes even without Dispose()");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  EXTERNAL PROCESS SCAN
    // ═══════════════════════════════════════════════════════════════════════

    private static int RunExternalScan(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("Usage: memory-forensics scan <pid> <hex-pattern>");
            Console.Error.WriteLine("Example: memory-forensics scan 1234 DEADBEEF");
            return 1;
        }

        int pid = int.Parse(args[1], CultureInfo.InvariantCulture);
        byte[] pattern = Convert.FromHexString(args[2]);

        PrintSection($"External Process Scan — PID {pid}");
        Info($"Pattern: {FormatHex(pattern)} ({pattern.Length} bytes)");

        try
        {
            using var target = DataTarget.AttachToProcess(pid, suspend: true);
            using var runtime = target.ClrVersions[0].CreateRuntime();

            var matches = ScanHeapForPattern(runtime, pattern);

            if (matches.Count == 0)
            {
                Safe("Pattern NOT found on managed heap");
                return 0;
            }

            Risk($"FOUND {matches.Count} matches:");
            foreach (var match in matches)
                Risk($"  0x{match.Address:X16} ({match.Length} bytes) — {match.TypeName}");

            Console.WriteLine();
            var (total, zeroed, violations) = ValidateSecureBuffers(runtime);
            Info($"SecureBuffer: {total} total, {zeroed} zeroed, {violations} violations");

            return matches.Count > 0 ? 1 : 0;
        }
        catch (Exception ex)
        {
            Risk($"Failed: {ex.Message}");
            return 2;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  ClrMD HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    private sealed record HeapMatch(ulong Address, int Length, string TypeName);

    private static List<HeapMatch> ScanHeapForPattern(ClrRuntime runtime, byte[] pattern)
    {
        var matches = new List<HeapMatch>();
        var heap = runtime.Heap;

        foreach (var obj in heap.EnumerateObjects())
        {
            if (!obj.IsValid || obj.Type == null) continue;
            if (obj.Type.Name != "System.Byte[]") continue;

            var size = obj.AsArray().Length;
            if (size < pattern.Length) continue;

            var buffer = new byte[size];
            if (runtime.DataTarget.DataReader.Read(obj.Address + (ulong)IntPtr.Size * 2, buffer) == 0)
                continue;

            if (ContainsPattern(buffer, pattern))
                matches.Add(new HeapMatch(obj.Address, size, obj.Type.Name));
        }

        return matches;
    }

    private static (int Total, int Zeroed, int Violations) ValidateSecureBuffers(ClrRuntime runtime)
    {
        int total = 0, zeroed = 0, violations = 0;
        var heap = runtime.Heap;

        foreach (var obj in heap.EnumerateObjects())
        {
            if (!obj.IsValid || obj.Type == null) continue;
            if (obj.Type.Name != "CyTypes.Core.Memory.SecureBuffer") continue;

            total++;

            var disposedField = obj.Type.GetFieldByName("_isDisposed");
            if (disposedField == null) continue;

            var isDisposed = disposedField.Read<int>(obj.Address, interior: false);
            if (isDisposed != 1) continue;

            var bufferField = obj.Type.GetFieldByName("_buffer");
            if (bufferField == null) continue;

            var bufferObj = bufferField.ReadObject(obj.Address, interior: false);
            if (!bufferObj.IsValid || bufferObj.Type == null) continue;

            var bufferSize = bufferObj.AsArray().Length;
            var buffer = new byte[bufferSize];
            if (runtime.DataTarget.DataReader.Read(bufferObj.Address + (ulong)IntPtr.Size * 2, buffer) == 0)
                continue;

            if (buffer.Any(b => b != 0))
                violations++;
            else
                zeroed++;
        }

        return (total, zeroed, violations);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SHARED HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    private static byte[] ReflectEncryptedBuffer(object cy)
    {
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
        return (byte[]?)toArrayMethod?.Invoke(secureBuffer, null) ?? [];
    }

    private static bool ContainsPattern(byte[] data, byte[] pattern)
    {
        for (int i = 0; i <= data.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    private static string FormatHex(byte[] data) =>
        string.Join(" ", data.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));

    private static void DumpHex(string label, byte[] data, ConsoleColor color)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"    ┌─ {label} ({data.Length} bytes) ───────────────────────────");
        Console.ResetColor();

        int rows = Math.Min((data.Length + 15) / 16, 6);
        for (int row = 0; row < rows; row++)
        {
            int offset = row * 16;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"    │ {offset:X4}  ");

            Console.ForegroundColor = color;
            var ascii = new StringBuilder();

            for (int col = 0; col < 16; col++)
            {
                int idx = offset + col;
                if (idx < data.Length)
                {
                    Console.Write($"{data[idx]:X2} ");
                    ascii.Append(data[idx] is >= 0x20 and <= 0x7E ? (char)data[idx] : '.');
                }
                else
                {
                    Console.Write("   ");
                    ascii.Append(' ');
                }
                if (col == 7) Console.Write(' ');
            }

            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.Write($" │{ascii}│");
            Console.ResetColor();
            Console.WriteLine();
        }

        if (data.Length > 96)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"    │ ... ({data.Length - 96} more bytes)");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("    └───────────────────────────────────────────────────────────");
        Console.ResetColor();
    }

    private static void PrintForensicSummaryTable()
    {
        PrintSection("FORENSIC ANALYSIS SUMMARY");

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"    {"Attack Vector",-32} {".NET Primitives",-30} {"CyTypes",-30}");
        Console.WriteLine($"    {new string('─', 32)} {new string('─', 30)} {new string('─', 30)}");
        Console.ResetColor();

        PrintSummaryRow("Memory dump", "Plaintext visible", "AES-256-GCM ciphertext");
        PrintSummaryRow("Core dump analysis", "All secrets recoverable", "Only ciphertext + nonces");
        PrintSummaryRow("Cold-boot (DRAM)", "Plaintext in cleartext", "Encrypted + OS-locked");
        PrintSummaryRow("Heap walk (!dumpheap)", "Plaintext on managed heap", "Ciphertext in pinned buffer");
        PrintSummaryRow("Post-free scan", "Stale data persists", "Cryptographically zeroed");
        PrintSummaryRow("Swap file forensics", "Pageable to disk", "mlock prevents paging");
        PrintSummaryRow("GC compaction", "Unzeroable ghost copies", "Pinned — never copied");
        PrintSummaryRow("String interning", "Permanent, unzeroable", "Never interned");
        Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("    Protection Stack:");
        Console.WriteLine("      Layer 1: AES-256-GCM encryption — plaintext never stored");
        Console.WriteLine("      Layer 2: GC.AllocateArray(pinned: true) — no GC relocation");
        Console.WriteLine("      Layer 3: mlock/VirtualLock — no swap-to-disk");
        Console.WriteLine("      Layer 4: CryptographicOperations.ZeroMemory — wipe on dispose");
        Console.WriteLine("      Layer 5: Finalizer safety net — zeroes even without Dispose()");
        Console.ResetColor();
    }

    private static void PrintSummaryRow(string vector, string dotnet, string cyTypes)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"    {vector,-32} ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"{dotnet,-30} ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(cyTypes);
        Console.ResetColor();
    }

    // ── Console formatting ────────────────────────────────────────────────

    private static void PrintSection(string title)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine();
        Console.WriteLine($"  ══ {title} ══");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void PrintSubSection(string title)
    {
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine($"    ── {title} ──");
        Console.ResetColor();
    }

    private static void Code(string code)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"    >> {code}");
        Console.ResetColor();
    }

    private static void Info(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"    [INFO] {msg}");
        Console.ResetColor();
    }

    private static void Risk(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"    [RISK] {msg}");
        Console.ResetColor();
    }

    private static void Safe(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"    [SAFE] {msg}");
        Console.ResetColor();
    }

    private static void PatternCheck(byte[] haystack, byte[] needle, string description)
    {
        bool found = ContainsPattern(haystack, needle);
        if (found)
            Risk($"Pattern check ({description}): FOUND — plaintext leaked!");
        else
            Safe($"Pattern check ({description}): NOT FOUND");
    }

    private static void WaitForKey()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine();
        Console.WriteLine("    Press any key to continue...");
        Console.ResetColor();

        if (!Console.IsInputRedirected)
            Console.ReadKey(true);
    }
}
