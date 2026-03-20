namespace CyTypes.Examples.Helpers;

public static class ConsoleHelpers
{
    public static void PrintHeader(string title)
    {
        var line = new string('=', title.Length + 4);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine();
        Console.WriteLine(line);
        Console.WriteLine($"  {title}");
        Console.WriteLine(line);
        Console.ResetColor();
        Console.WriteLine();
    }

    public static void PrintSubHeader(string title)
    {
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine($"--- {title} ---");
        Console.ResetColor();
    }

    public static void PrintRisk(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  [RISK] {message}");
        Console.ResetColor();
    }

    public static void PrintSecure(string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  [SAFE] {message}");
        Console.ResetColor();
    }

    public static void PrintInfo(string message)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  [INFO] {message}");
        Console.ResetColor();
    }

    public static void PrintComparison(string label, string dotnet, string cyTypes)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"  {label,-25}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($".NET: {dotnet,-30}");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"CyTypes: {cyTypes}");
        Console.ResetColor();
    }

    public static void PrintNote(string message)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"         {message}");
        Console.ResetColor();
    }

    public static void PrintCode(string code)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  >> {code}");
        Console.ResetColor();
    }

    public static void PrintLine()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(new string('-', 70));
        Console.ResetColor();
    }
}
