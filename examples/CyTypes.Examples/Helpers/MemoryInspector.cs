using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using CyTypes.Primitives.Shared;

namespace CyTypes.Examples.Helpers;

public static class MemoryInspector
{
    public static unsafe void DumpValueMemory<T>(ref T value, string label) where T : unmanaged
    {
        fixed (T* ptr = &value)
        {
            var bytePtr = (byte*)ptr;
            int size = sizeof(T);
            var hex = new StringBuilder();
            var readable = new StringBuilder();

            for (int i = 0; i < size && i < 32; i++)
            {
                hex.Append(CultureInfo.InvariantCulture, $"{bytePtr[i]:X2} ");
                readable.Append(bytePtr[i] is >= 0x20 and <= 0x7E ? (char)bytePtr[i] : '.');
            }

            var address = ((nint)ptr).ToString("X", CultureInfo.InvariantCulture);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  [{label}] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"Address: 0x{address} | ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"Hex: {hex}");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"| Readable: {readable}");
            Console.ResetColor();
        }
    }

    public static unsafe void DumpStringMemory(string s, string label)
    {
        fixed (char* ptr = s)
        {
            var hex = new StringBuilder();
            var readable = new StringBuilder();
            int len = Math.Min(s.Length, 16);

            for (int i = 0; i < len; i++)
            {
                byte lo = (byte)(ptr[i] & 0xFF);
                byte hi = (byte)((ptr[i] >> 8) & 0xFF);
                hex.Append(CultureInfo.InvariantCulture, $"{lo:X2} {hi:X2} ");
                readable.Append(ptr[i] is >= (char)0x20 and <= (char)0x7E ? ptr[i] : '.');
            }

            var address = ((nint)ptr).ToString("X", CultureInfo.InvariantCulture);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  [{label}] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"Address: 0x{address} | ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"Hex: {hex}");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"| Readable: {readable}");
            Console.ResetColor();
        }
    }

    public static void DumpByteArrayMemory(byte[] arr, string label)
    {
        var handle = GCHandle.Alloc(arr, GCHandleType.Pinned);
        try
        {
            var ptr = handle.AddrOfPinnedObject();
            var hex = new StringBuilder();
            var readable = new StringBuilder();
            int len = Math.Min(arr.Length, 32);

            for (int i = 0; i < len; i++)
            {
                hex.Append(CultureInfo.InvariantCulture, $"{arr[i]:X2} ");
                readable.Append(arr[i] is >= 0x20 and <= 0x7E ? (char)arr[i] : '.');
            }

            if (arr.Length > 32)
                hex.Append("...");

            var address = ptr.ToString("X", CultureInfo.InvariantCulture);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  [{label}] ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"Address: 0x{address} | ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"Hex: {hex}");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"| Readable: {readable}");
            Console.ResetColor();
        }
        finally
        {
            handle.Free();
        }
    }

    public static void DumpCyTypeInfo(ICyType cy, string label)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  [{label}] ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"ToString: {cy} | ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"Compromised: {cy.IsCompromised} | ");
        Console.Write($"Tainted: {cy.IsTainted} | ");
        Console.WriteLine($"Policy: {cy.Policy}");
        Console.ResetColor();
    }
}
