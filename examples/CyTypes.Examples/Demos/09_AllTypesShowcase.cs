using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class AllTypesShowcase
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 9: All 10 CyTypes Showcase");

        ConsoleHelpers.PrintNote("Protection is at the MEMORY level. Below, we verify IsCompromised=False on");
        ConsoleHelpers.PrintNote("operation results BEFORE any ToInsecure*() — proving they stay encrypted.");
        Console.WriteLine();

        ShowCyInt();
        ShowCyLong();
        ShowCyDouble();
        ShowCyFloat();
        ShowCyDecimal();
        ShowCyBool();
        ShowCyString();
        ShowCyBytes();
        ShowCyGuid();
        ShowCyDateTime();
    }

    private static void ShowCyInt()
    {
        ConsoleHelpers.PrintSubHeader("1. CyInt - Encrypted 32-bit Integer");
        using var a = new CyInt(100);
        using var b = new CyInt(37);

        // Arithmetic
        using var sum = a + b;
        using var diff = a - b;
        using var prod = a * b;
        using var div = a / b;
        using var mod = a % b;

        ConsoleHelpers.PrintCode("var a = new CyInt(100); var b = new CyInt(37);");
        ConsoleHelpers.PrintCode("var sum = a + b;");
        ConsoleHelpers.PrintCode("sum.IsCompromised  // before any ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {sum.IsCompromised}");
        ConsoleHelpers.PrintNote("Arithmetic in secure enclave — plaintext never exposed to managed memory.");

        ConsoleHelpers.PrintCode("sum.ToInsecureInt(), diff.ToInsecureInt()");
        ConsoleHelpers.PrintInfo($"=> 100 + 37 = {sum.ToInsecureInt()}, 100 - 37 = {diff.ToInsecureInt()}");
        ConsoleHelpers.PrintCode("prod.ToInsecureInt(), div.ToInsecureInt(), mod.ToInsecureInt()");
        ConsoleHelpers.PrintInfo($"=> 100 * 37 = {prod.ToInsecureInt()}, 100 / 37 = {div.ToInsecureInt()}, 100 %% 37 = {mod.ToInsecureInt()}");

        // Bitwise
        using var x = new CyInt(0b1010);
        using var y = new CyInt(0b1100);
        using var andR = x & y;
        using var orR = x | y;
        using var xorR = x ^ y;
        using var notR = ~x;
        using var shl = x << 2;
        using var shr = x >> 1;

        ConsoleHelpers.PrintCode("var x = new CyInt(0b1010); var y = new CyInt(0b1100);");
        ConsoleHelpers.PrintCode("var andR = x & y;");
        ConsoleHelpers.PrintCode("andR.IsCompromised  // before any ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {andR.IsCompromised}");
        ConsoleHelpers.PrintCode("andR.ToInsecureInt(), orR.ToInsecureInt(), xorR.ToInsecureInt()");
        ConsoleHelpers.PrintInfo($"=> & = {andR.ToInsecureInt()}, | = {orR.ToInsecureInt()}, ^ = {xorR.ToInsecureInt()}");
        ConsoleHelpers.PrintCode("(~x).ToInsecureInt(), (x << 2).ToInsecureInt(), (x >> 1).ToInsecureInt()");
        ConsoleHelpers.PrintInfo($"=> ~ = {notR.ToInsecureInt()}, << 2 = {shl.ToInsecureInt()}, >> 1 = {shr.ToInsecureInt()}");

        ConsoleHelpers.PrintCode("a.ToString()");
        ConsoleHelpers.PrintInfo($"=> {a}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyLong()
    {
        ConsoleHelpers.PrintSubHeader("2. CyLong - Encrypted 64-bit Integer");
        using var a = new CyLong(1_000_000_000_000L);
        using var b = new CyLong(500_000_000_000L);
        using var sum = a + b;

        ConsoleHelpers.PrintCode("var a = new CyLong(1_000_000_000_000L);");
        ConsoleHelpers.PrintCode("var sum = a + new CyLong(500_000_000_000L);");
        ConsoleHelpers.PrintCode("sum.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {sum.IsCompromised}");
        ConsoleHelpers.PrintCode("sum.ToInsecureLong()");
        ConsoleHelpers.PrintInfo($"=> {sum.ToInsecureLong():N0}");
        ConsoleHelpers.PrintCode("a.ToString()");
        ConsoleHelpers.PrintInfo($"=> {a}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyDouble()
    {
        ConsoleHelpers.PrintSubHeader("3. CyDouble - Encrypted Double");
        using var pi = new CyDouble(Math.PI);
        using var e = new CyDouble(Math.E);
        using var sum = pi + e;
        using var prod = pi * e;

        ConsoleHelpers.PrintCode("var pi = new CyDouble(Math.PI);");
        ConsoleHelpers.PrintCode("var e = new CyDouble(Math.E);");
        ConsoleHelpers.PrintCode("var sum = pi + e;");
        ConsoleHelpers.PrintCode("sum.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {sum.IsCompromised}");
        ConsoleHelpers.PrintNote("Arithmetic in secure enclave — plaintext never exposed to managed memory.");
        ConsoleHelpers.PrintCode("sum.ToInsecureDouble()");
        ConsoleHelpers.PrintInfo($"=> {sum.ToInsecureDouble():F10}");
        ConsoleHelpers.PrintCode("prod.ToInsecureDouble()");
        ConsoleHelpers.PrintInfo($"=> {prod.ToInsecureDouble():F10}");
        ConsoleHelpers.PrintCode("pi.ToString()");
        ConsoleHelpers.PrintInfo($"=> {pi}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyFloat()
    {
        ConsoleHelpers.PrintSubHeader("4. CyFloat - Encrypted Float");
        using var a = new CyFloat(1.5f);
        using var b = new CyFloat(2.5f);
        using var sum = a + b;

        ConsoleHelpers.PrintCode("var a = new CyFloat(1.5f); var b = new CyFloat(2.5f);");
        ConsoleHelpers.PrintCode("var sum = a + b;");
        ConsoleHelpers.PrintCode("sum.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {sum.IsCompromised}");
        ConsoleHelpers.PrintNote("Arithmetic in secure enclave — plaintext never exposed to managed memory.");
        ConsoleHelpers.PrintCode("sum.ToInsecureFloat()");
        ConsoleHelpers.PrintInfo($"=> {sum.ToInsecureFloat()}");
        ConsoleHelpers.PrintCode("a.ToString()");
        ConsoleHelpers.PrintInfo($"=> {a}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyDecimal()
    {
        ConsoleHelpers.PrintSubHeader("5. CyDecimal - Encrypted Decimal (Financial Precision)");
        ConsoleHelpers.PrintNote("128-bit decimal precision — ideal for financial calculations (no IEEE 754 rounding).");

        using var price = new CyDecimal(29.99m);
        using var tax = new CyDecimal(0.08m);
        using var total = price + (price * tax);

        ConsoleHelpers.PrintCode("var price = new CyDecimal(29.99m);");
        ConsoleHelpers.PrintCode("var tax = new CyDecimal(0.08m);");
        ConsoleHelpers.PrintCode("var total = price + (price * tax);");
        ConsoleHelpers.PrintCode("total.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {total.IsCompromised}");
        ConsoleHelpers.PrintNote("Arithmetic in secure enclave — plaintext never exposed to managed memory.");
        ConsoleHelpers.PrintCode("total.ToInsecureDecimal()");
        ConsoleHelpers.PrintInfo($"=> ${total.ToInsecureDecimal():F2}");
        ConsoleHelpers.PrintCode("price.ToString()");
        ConsoleHelpers.PrintInfo($"=> {price}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyBool()
    {
        ConsoleHelpers.PrintSubHeader("6. CyBool - Encrypted Boolean");
        using var t = new CyBool(true);
        using var f = new CyBool(false);

        using var andR = t & f;
        using var orR = t | f;
        using var xorR = t ^ f;
        using var notR = !t;

        ConsoleHelpers.PrintCode("var t = new CyBool(true); var f = new CyBool(false);");
        ConsoleHelpers.PrintCode("var andR = t & f;");
        ConsoleHelpers.PrintCode("andR.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {andR.IsCompromised}");
        ConsoleHelpers.PrintNote("Logic ops in secure enclave — plaintext never exposed to managed memory.");
        ConsoleHelpers.PrintCode("andR.ToInsecureBool()");
        ConsoleHelpers.PrintInfo($"=> true & false = {andR.ToInsecureBool()}");
        ConsoleHelpers.PrintCode("orR.ToInsecureBool()");
        ConsoleHelpers.PrintInfo($"=> true | false = {orR.ToInsecureBool()}");
        ConsoleHelpers.PrintCode("xorR.ToInsecureBool()");
        ConsoleHelpers.PrintInfo($"=> true ^ false = {xorR.ToInsecureBool()}");
        ConsoleHelpers.PrintCode("(!t).ToInsecureBool()");
        ConsoleHelpers.PrintInfo($"=> !true = {notR.ToInsecureBool()}");
        ConsoleHelpers.PrintCode("t.ToString()");
        ConsoleHelpers.PrintInfo($"=> {t}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyString()
    {
        ConsoleHelpers.PrintSubHeader("7. CyString - Encrypted String");
        using var greeting = new CyString("Hello, CyTypes!");

        // Concat
        using var world = new CyString(" Welcome to secure strings.");
        using var combined = CyString.Concat(greeting, world);

        ConsoleHelpers.PrintCode("var greeting = new CyString(\"Hello, CyTypes!\");");
        ConsoleHelpers.PrintCode("var world = new CyString(\" Welcome to secure strings.\");");
        ConsoleHelpers.PrintCode("var combined = CyString.Concat(greeting, world);");
        ConsoleHelpers.PrintCode("combined.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {combined.IsCompromised}");
        ConsoleHelpers.PrintNote("Concatenation in secure enclave — re-encrypts the result immediately.");
        ConsoleHelpers.PrintCode("combined.ToInsecureString()");
        ConsoleHelpers.PrintInfo($"=> \"{combined.ToInsecureString()}\"");

        // Substring
        using var sub = greeting.Substring(7, 7);
        ConsoleHelpers.PrintCode("greeting.Substring(7, 7).ToInsecureString()");
        ConsoleHelpers.PrintInfo($"=> \"{sub.ToInsecureString()}\"");

        // ToUpper
        using var upper = greeting.ToUpper();
        ConsoleHelpers.PrintCode("greeting.ToUpper().ToInsecureString()");
        ConsoleHelpers.PrintInfo($"=> \"{upper.ToInsecureString()}\"");

        // Contains
        ConsoleHelpers.PrintCode("greeting.Contains(\"CyTypes\")");
        bool contains = greeting.Contains("CyTypes");
        ConsoleHelpers.PrintInfo($"=> {contains}");

        // Split
        using var csv = new CyString("one,two,three");
        ConsoleHelpers.PrintCode("new CyString(\"one,two,three\").Split(',')");
        var parts = csv.Split(',');
        ConsoleHelpers.PrintInfo($"=> [{string.Join(", ", parts.Select(p => { var s = p.ToInsecureString(); p.Dispose(); return $"\"{s}\""; }))}]");

        // SecureEquals (constant-time)
        using var a = new CyString("secret");
        using var b = new CyString("secret");
        ConsoleHelpers.PrintCode("new CyString(\"secret\").SecureEquals(new CyString(\"secret\"))");
        ConsoleHelpers.PrintInfo($"=> {a.SecureEquals(b)} (constant-time HMAC comparison)");

        // Indexer marks compromise
        using var idx = new CyString("ABCD");
        ConsoleHelpers.PrintCode("var idx = new CyString(\"ABCD\"); char c = idx[0];");
        char c = idx[0];
        ConsoleHelpers.PrintRisk($"c = '{c}', idx.IsCompromised = {idx.IsCompromised}");

        ConsoleHelpers.PrintCode("greeting.ToString()");
        ConsoleHelpers.PrintInfo($"=> {greeting}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyBytes()
    {
        ConsoleHelpers.PrintSubHeader("8. CyBytes - Encrypted Byte Array");
        byte[] raw = [0x01, 0x02, 0x03, 0xDE, 0xAD, 0xBE, 0xEF];
        using var cyb = new CyBytes(raw);

        ConsoleHelpers.PrintCode("var cyb = new CyBytes([0x01, 0x02, 0x03, 0xDE, 0xAD, 0xBE, 0xEF]);");
        ConsoleHelpers.PrintCode("cyb.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {cyb.IsCompromised}");
        ConsoleHelpers.PrintCode("cyb.Length  // metadata, no decryption needed");
        ConsoleHelpers.PrintInfo($"=> {cyb.Length}");
        ConsoleHelpers.PrintCode("cyb.ToString()");
        ConsoleHelpers.PrintInfo($"=> {cyb}");

        ConsoleHelpers.PrintCode("cyb.ToInsecureBytes()");
        byte[] decrypted = cyb.ToInsecureBytes();
        ConsoleHelpers.PrintInfo($"=> [{string.Join(", ", decrypted.Select(b => $"0x{b:X2}"))}]");
        ConsoleHelpers.PrintCode("cyb.IsCompromised  // after ToInsecureBytes()");
        ConsoleHelpers.PrintRisk($"=> {cyb.IsCompromised}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyGuid()
    {
        ConsoleHelpers.PrintSubHeader("9. CyGuid - Encrypted GUID");
        var original = Guid.NewGuid();
        using var cyg = new CyGuid(original);

        ConsoleHelpers.PrintCode("var cyg = new CyGuid(Guid.NewGuid());");
        ConsoleHelpers.PrintCode("cyg.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {cyg.IsCompromised}");
        ConsoleHelpers.PrintCode("cyg.ToString()");
        ConsoleHelpers.PrintInfo($"=> {cyg}");
        ConsoleHelpers.PrintCode("cyg.ToInsecureGuid()");
        Guid decrypted = cyg.ToInsecureGuid();
        ConsoleHelpers.PrintInfo($"=> {decrypted}");
        ConsoleHelpers.PrintInfo($"Values match: {original == decrypted}");
        ConsoleHelpers.PrintCode("cyg.IsCompromised  // after ToInsecureGuid()");
        ConsoleHelpers.PrintRisk($"=> {cyg.IsCompromised}");
        ConsoleHelpers.PrintLine();
    }

    private static void ShowCyDateTime()
    {
        ConsoleHelpers.PrintSubHeader("10. CyDateTime - Encrypted DateTime");
        var now = DateTime.UtcNow;
        using var cydt = new CyDateTime(now);
        using var past = new CyDateTime(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        ConsoleHelpers.PrintCode("var cydt = new CyDateTime(DateTime.UtcNow);");
        ConsoleHelpers.PrintCode("cydt.IsCompromised  // before ToInsecure*()");
        ConsoleHelpers.PrintSecure($"=> {cydt.IsCompromised}");
        ConsoleHelpers.PrintCode("cydt.ToString()");
        ConsoleHelpers.PrintInfo($"=> {cydt}");
        ConsoleHelpers.PrintCode("cydt.ToInsecureDateTime()");
        ConsoleHelpers.PrintInfo($"=> {cydt.ToInsecureDateTime():O}");

        ConsoleHelpers.PrintCode("cydt > new CyDateTime(new DateTime(2000, 1, 1))");
        bool isAfter = cydt > past;
        ConsoleHelpers.PrintInfo($"=> {isAfter}");
        ConsoleHelpers.PrintCode("cydt.IsCompromised  // after ToInsecureDateTime()");
        ConsoleHelpers.PrintRisk($"=> {cydt.IsCompromised}");
        ConsoleHelpers.PrintLine();
    }
}
