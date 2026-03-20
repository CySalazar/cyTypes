using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class BasicUsage
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 1: Basic Usage - CyTypes vs .NET Primitives");

        ConsoleHelpers.PrintNote("CyTypes are drop-in replacements for .NET primitives with AES-256-GCM encryption");
        ConsoleHelpers.PrintNote("in pinned/locked memory buffers. Protection is at the MEMORY level.");
        Console.WriteLine();

        // --- CyInt ---
        ConsoleHelpers.PrintSubHeader("CyInt - Encrypted Integer");

        int x = 42;
        CyInt cx = 42;  // implicit conversion

        ConsoleHelpers.PrintCode("int x = 42;");
        ConsoleHelpers.PrintInfo($".NET int x = {x}");
        Console.WriteLine();

        ConsoleHelpers.PrintCode("CyInt cx = 42;  // implicit conversion");
        ConsoleHelpers.PrintCode("cx.ToString()");
        ConsoleHelpers.PrintInfo($"=> {cx}");
        ConsoleHelpers.PrintNote("ToString() returns redacted metadata because the plaintext is encrypted in memory —");
        ConsoleHelpers.PrintNote("there is no cleartext to return. This is a consequence of the protection, not the cause.");
        Console.WriteLine();

        // Arithmetic — result stays encrypted
        CyInt cy = 58;
        CyInt sum = cx + cy;

        ConsoleHelpers.PrintCode("CyInt cy = 58;");
        ConsoleHelpers.PrintCode("CyInt sum = cx + cy;");
        ConsoleHelpers.PrintCode("sum.IsCompromised");
        ConsoleHelpers.PrintSecure($"=> {sum.IsCompromised}");
        ConsoleHelpers.PrintNote("The result is encrypted without ever calling ToString() or ToInsecure*().");
        ConsoleHelpers.PrintNote("Arithmetic happens in a secure enclave; the plaintext result is immediately re-encrypted.");
        Console.WriteLine();

        // Explicit decryption marks compromise
        ConsoleHelpers.PrintCode("int decrypted = cx.ToInsecureInt();");
        int decrypted = cx.ToInsecureInt();
        ConsoleHelpers.PrintRisk($"decrypted = {decrypted}, cx.IsCompromised = {cx.IsCompromised}");
        Console.WriteLine();

        // ToString() after compromise — still redacted
        ConsoleHelpers.PrintCode("cx.ToString()  // after ToInsecureInt()");
        ConsoleHelpers.PrintInfo($"=> {cx}");
        ConsoleHelpers.PrintNote("Still redacted — ToString() never exposes plaintext, regardless of compromise state.");

        // using pattern for disposal
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Disposal Pattern");
        ConsoleHelpers.PrintCode("using (var temp = new CyInt(100)) { ... }");
        using (var temp = new CyInt(100))
        {
            ConsoleHelpers.PrintInfo($"Inside using block: {temp}");
        }
        ConsoleHelpers.PrintSecure("After using block: memory zeroed, instance disposed");

        // --- CyLong ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("CyLong - Encrypted 64-bit Integer");
        CyLong cl = 9_876_543_210L;

        ConsoleHelpers.PrintCode("CyLong cl = 9_876_543_210L;");
        ConsoleHelpers.PrintCode("cl.ToString()");
        ConsoleHelpers.PrintInfo($"=> {cl}");

        ConsoleHelpers.PrintCode("cl.ToInsecureLong()  // only way to get plaintext — marks as compromised");
        ConsoleHelpers.PrintRisk($"=> {cl.ToInsecureLong()}, cl.IsCompromised = {cl.IsCompromised}");

        // --- CyDouble ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("CyDouble - Encrypted Double");
        CyDouble cd = 3.14159265;
        CyDouble cd2 = 2.71828;
        CyDouble dSum = cd + cd2;

        ConsoleHelpers.PrintCode("CyDouble cd = 3.14159265;");
        ConsoleHelpers.PrintCode("CyDouble cd2 = 2.71828;");
        ConsoleHelpers.PrintCode("CyDouble dSum = cd + cd2;");
        ConsoleHelpers.PrintCode("dSum.ToString()");
        ConsoleHelpers.PrintInfo($"=> {dSum}");

        ConsoleHelpers.PrintCode("dSum.ToInsecureDouble()  // only way to get plaintext — marks as compromised");
        ConsoleHelpers.PrintRisk($"=> {dSum.ToInsecureDouble():F5}, dSum.IsCompromised = {dSum.IsCompromised}");

        // --- CyFloat ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("CyFloat - Encrypted Float");
        CyFloat cf = 1.23f;

        ConsoleHelpers.PrintCode("CyFloat cf = 1.23f;");
        ConsoleHelpers.PrintCode("cf.ToString()");
        ConsoleHelpers.PrintInfo($"=> {cf}");

        ConsoleHelpers.PrintCode("cf.ToInsecureFloat()  // only way to get plaintext — marks as compromised");
        ConsoleHelpers.PrintRisk($"=> {cf.ToInsecureFloat()}, cf.IsCompromised = {cf.IsCompromised}");

        // --- CyDecimal ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("CyDecimal - Encrypted Decimal (Financial Precision)");
        CyDecimal price = new CyDecimal(19.99m);
        CyDecimal qty = new CyDecimal(3m);
        CyDecimal total = price * qty;

        ConsoleHelpers.PrintCode("CyDecimal price = new CyDecimal(19.99m);");
        ConsoleHelpers.PrintCode("CyDecimal qty = new CyDecimal(3m);");
        ConsoleHelpers.PrintCode("CyDecimal total = price * qty;");
        ConsoleHelpers.PrintCode("total.ToString()");
        ConsoleHelpers.PrintInfo($"=> {total}");

        ConsoleHelpers.PrintCode("total.ToInsecureDecimal()  // only way to get plaintext — marks as compromised");
        ConsoleHelpers.PrintRisk($"=> {total.ToInsecureDecimal()}, total.IsCompromised = {total.IsCompromised}");

        // --- Inter-CyType Operations Remain Encrypted ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("Inter-CyType Operations Remain Encrypted");

        using var p = new CyInt(500);
        using var q = new CyInt(300);
        using var result = p + q;

        ConsoleHelpers.PrintCode("var p = new CyInt(500);");
        ConsoleHelpers.PrintCode("var q = new CyInt(300);");
        ConsoleHelpers.PrintCode("var result = p + q;");
        Console.WriteLine();
        ConsoleHelpers.PrintCode("result.IsCompromised");
        ConsoleHelpers.PrintSecure($"=> {result.IsCompromised}");
        ConsoleHelpers.PrintCode("result.IsTainted");
        ConsoleHelpers.PrintSecure($"=> {result.IsTainted}");
        ConsoleHelpers.PrintNote("No ToInsecure*() was called — the plaintext of 'result' has never been exposed.");

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("Key takeaway: CyTypes are drop-in replacements with always-encrypted memory.");

        // Dispose all
        cx.Dispose();
        cy.Dispose();
        sum.Dispose();
        cl.Dispose();
        cd.Dispose();
        cd2.Dispose();
        dSum.Dispose();
        cf.Dispose();
        price.Dispose();
        qty.Dispose();
        total.Dispose();
    }
}
