namespace CyTypes.NativeExport;

/// <summary>
/// Thread-local error state for the C API.
/// Each calling thread gets its own last-error message,
/// similar to Win32 GetLastError() / errno.
/// </summary>
internal static class ErrorState
{
    [ThreadStatic]
    private static string? _lastError;

    public static void Set(string message) => _lastError = message;
    public static void Clear() => _lastError = null;
    public static string? Get() => _lastError;
}
