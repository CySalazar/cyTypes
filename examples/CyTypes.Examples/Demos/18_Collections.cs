using CyTypes.Collections;
using CyTypes.Examples.Helpers;
using CyTypes.Primitives;

namespace CyTypes.Examples.Demos;

public static class CollectionsDemo
{
    public static void Run()
    {
        ConsoleHelpers.PrintHeader("Demo 18: Encrypted Collections — CyList<T> and CyDictionary<TKey, TValue>");

        ConsoleHelpers.PrintNote("CyList and CyDictionary hold encrypted CyType elements.");
        ConsoleHelpers.PrintNote("They automatically dispose elements on removal and on Dispose().");
        Console.WriteLine();

        // --- CyList ---
        ConsoleHelpers.PrintSubHeader("CyList<CyInt> — Encrypted List");

        ConsoleHelpers.PrintCode("using var list = new CyList<CyInt>();");
        ConsoleHelpers.PrintCode("list.Add(new CyInt(10));");
        ConsoleHelpers.PrintCode("list.Add(new CyInt(20));");
        ConsoleHelpers.PrintCode("list.Add(new CyInt(30));");

        using var list = new CyList<CyInt>();
        list.Add(new CyInt(10));
        list.Add(new CyInt(20));
        list.Add(new CyInt(30));

        ConsoleHelpers.PrintInfo($"Count: {list.Count}");
        ConsoleHelpers.PrintInfo($"list[0]: {list[0]}");
        ConsoleHelpers.PrintNote("ToString() is redacted — elements are encrypted in memory.");
        Console.WriteLine();

        // Iterate
        ConsoleHelpers.PrintSubHeader("Iteration");
        ConsoleHelpers.PrintCode("foreach (var item in list) { ... }");
        int i = 0;
        foreach (var item in list)
        {
            ConsoleHelpers.PrintInfo($"[{i}] = {item.ToInsecureInt()}");
            i++;
        }
        Console.WriteLine();

        // AddRange
        ConsoleHelpers.PrintSubHeader("AddRange and RemoveAll");
        ConsoleHelpers.PrintCode("list.AddRange(new[] { new CyInt(40), new CyInt(50) });");
        list.AddRange(new[] { new CyInt(40), new CyInt(50) });
        ConsoleHelpers.PrintInfo($"Count after AddRange: {list.Count}");

        ConsoleHelpers.PrintCode("list.RemoveAll(x => x.ToInsecureInt() > 25);");
        int removed = list.RemoveAll(x => x.ToInsecureInt() > 25);
        ConsoleHelpers.PrintInfo($"Removed {removed} items, remaining: {list.Count}");
        ConsoleHelpers.PrintSecure("Removed elements were automatically disposed (memory zeroed).");
        Console.WriteLine();

        // DetachAt
        ConsoleHelpers.PrintSubHeader("DetachAt — Remove Without Disposing");
        ConsoleHelpers.PrintCode("var detached = list.DetachAt(0);");
        var detached = list.DetachAt(0);
        ConsoleHelpers.PrintInfo($"Detached value: {detached.ToInsecureInt()}");
        ConsoleHelpers.PrintInfo($"detached.IsDisposed = {detached.IsDisposed}");
        ConsoleHelpers.PrintNote("DetachAt() transfers ownership to the caller — you must dispose it yourself.");
        detached.Dispose();
        Console.WriteLine();

        // --- CyDictionary ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("CyDictionary<string, CyString> — Encrypted Dictionary");

        ConsoleHelpers.PrintCode("using var dict = new CyDictionary<string, CyString>();");
        ConsoleHelpers.PrintCode("dict[\"email\"] = new CyString(\"alice@example.com\");");
        ConsoleHelpers.PrintCode("dict[\"ssn\"]   = new CyString(\"123-45-6789\");");

        using var dict = new CyDictionary<string, CyString>();
        dict["email"] = new CyString("alice@example.com");
        dict["ssn"] = new CyString("123-45-6789");

        ConsoleHelpers.PrintInfo($"Count: {dict.Count}");
        ConsoleHelpers.PrintInfo($"dict[\"email\"]: {dict["email"]}");
        ConsoleHelpers.PrintNote("Values are encrypted — keys are plain strings (not sensitive).");
        Console.WriteLine();

        // TryGetValue
        ConsoleHelpers.PrintCode("dict.TryGetValue(\"ssn\", out var ssn)");
        if (dict.TryGetValue("ssn", out var ssn))
        {
            ConsoleHelpers.PrintRisk($"SSN decrypted: {ssn.ToInsecureString()}");
        }
        Console.WriteLine();

        // Overwrite disposes old value
        ConsoleHelpers.PrintSubHeader("Overwrite Disposes Old Value");
        ConsoleHelpers.PrintCode("dict[\"email\"] = new CyString(\"bob@example.com\");");
        dict["email"] = new CyString("bob@example.com");
        ConsoleHelpers.PrintSecure("Old \"alice@example.com\" was automatically disposed.");
        ConsoleHelpers.PrintInfo($"New value: {dict["email"].ToInsecureString()}");
        Console.WriteLine();

        // --- ToCyList LINQ extension ---
        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSubHeader("ToCyList() LINQ Extension");
        ConsoleHelpers.PrintCode("var numbers = Enumerable.Range(1, 5).Select(n => new CyInt(n)).ToCyList();");
        using var numbers = Enumerable.Range(1, 5).Select(n => new CyInt(n)).ToCyList();
        ConsoleHelpers.PrintInfo($"Count: {numbers.Count}");
        numbers.ForEach(n => Console.Write($"  {n.ToInsecureInt()}"));
        Console.WriteLine();
        Console.WriteLine();

        ConsoleHelpers.PrintLine();
        ConsoleHelpers.PrintSecure("All elements disposed automatically when the collection is disposed.");
    }
}
