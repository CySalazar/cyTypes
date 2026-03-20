using System.Runtime.InteropServices;

namespace CyTypes.Core.Memory;

/// <summary>
/// Provides OS-level memory locking (mlock/VirtualLock) to prevent pages from being swapped to disk.
/// </summary>
public static class MemoryLock
{
    /// <summary>Gets a value indicating whether the current platform supports memory locking.</summary>
    public static bool IsLockingSupported { get; } =
        RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ||
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    /// <summary>Attempts to lock the specified memory region to prevent it from being paged out.</summary>
    /// <param name="address">The starting address of the memory region.</param>
    /// <param name="length">The length of the memory region in bytes.</param>
    /// <returns><c>true</c> if the memory was successfully locked; otherwise, <c>false</c>.</returns>
    public static bool TryLock(IntPtr address, nuint length)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return Posix.mlock(address, length) == 0;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Windows.VirtualLock(address, length);
        }

        return false;
    }

    /// <summary>Attempts to unlock a previously locked memory region, allowing it to be paged.</summary>
    /// <param name="address">The starting address of the memory region.</param>
    /// <param name="length">The length of the memory region in bytes.</param>
    /// <returns><c>true</c> if the memory was successfully unlocked; otherwise, <c>false</c>.</returns>
    public static bool TryUnlock(IntPtr address, nuint length)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return Posix.munlock(address, length) == 0;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Windows.VirtualUnlock(address, length);
        }

        return false;
    }

    private static class Posix
    {
        [DllImport("libc", SetLastError = true)]
        public static extern int mlock(IntPtr addr, nuint len);

        [DllImport("libc", SetLastError = true)]
        public static extern int munlock(IntPtr addr, nuint len);
    }

    private static class Windows
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualLock(IntPtr lpAddress, nuint dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualUnlock(IntPtr lpAddress, nuint dwSize);
    }
}
