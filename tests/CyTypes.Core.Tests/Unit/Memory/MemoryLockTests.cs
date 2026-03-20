using System.Runtime.InteropServices;
using CyTypes.Core.Memory;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.Memory;

public sealed class MemoryLockTests
{
    [Fact]
    public void IsLockingSupported_ReturnsTrueOnMacOS()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // Skip assertion on non-macOS; the property should still be true
            // on Linux and Windows per the implementation.
            return;
        }

        MemoryLock.IsLockingSupported.Should().BeTrue();
    }

    [Fact]
    public void TryLockAndTryUnlock_ExecuteWithoutCrashing()
    {
        // Allocate a pinned buffer and attempt lock/unlock.
        // The calls may return false if RLIMIT_MEMLOCK is too low,
        // but they must not throw or crash.
        var data = GC.AllocateArray<byte>(4096, pinned: true);
        var handle = GCHandle.Alloc(data, GCHandleType.Pinned);

        try
        {
            var address = handle.AddrOfPinnedObject();
            var length = (nuint)data.Length;

            bool locked = false;
            var lockAct = () => { locked = MemoryLock.TryLock(address, length); };
            lockAct.Should().NotThrow();

            var unlockAct = () => MemoryLock.TryUnlock(address, length);
            unlockAct.Should().NotThrow();
        }
        finally
        {
            handle.Free();
        }
    }
}
