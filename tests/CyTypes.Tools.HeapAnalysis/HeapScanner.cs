using Microsoft.Diagnostics.Runtime;

namespace CyTypes.Tools.HeapAnalysis;

public record HeapMatch(ulong Address, int Length, string TypeName);

public record SecureBufferReport(int TotalFound, int ProperlyZeroed, int StillContainsData, List<HeapMatch> Violations);

public static class HeapScanner
{
    public static List<HeapMatch> ScanForPattern(DataTarget dataTarget, byte[] pattern)
    {
        var matches = new List<HeapMatch>();

        using var runtime = dataTarget.ClrVersions[0].CreateRuntime();
        var heap = runtime.Heap;

        foreach (var obj in heap.EnumerateObjects())
        {
            if (!obj.IsValid || obj.Type == null)
                continue;

            if (obj.Type.Name != "System.Byte[]")
                continue;

            var size = obj.AsArray().Length;
            if (size < pattern.Length)
                continue;

            var buffer = new byte[size];
            if (runtime.DataTarget.DataReader.Read(obj.Address + (ulong)IntPtr.Size * 2, buffer) == 0)
                continue;

            if (ContainsPattern(buffer, pattern))
            {
                matches.Add(new HeapMatch(obj.Address, size, obj.Type.Name));
            }
        }

        return matches;
    }

    public static SecureBufferReport ValidateSecureBuffers(DataTarget dataTarget)
    {
        var violations = new List<HeapMatch>();
        int totalFound = 0;
        int properlyZeroed = 0;
        int stillContainsData = 0;

        using var runtime = dataTarget.ClrVersions[0].CreateRuntime();
        var heap = runtime.Heap;

        foreach (var obj in heap.EnumerateObjects())
        {
            if (!obj.IsValid || obj.Type == null)
                continue;

            if (obj.Type.Name != "CyTypes.Core.Memory.SecureBuffer")
                continue;

            totalFound++;

            // Check _isDisposed field
            var disposedField = obj.Type.GetFieldByName("_isDisposed");
            if (disposedField == null) continue;

            var isDisposed = disposedField.Read<int>(obj.Address, interior: false);
            if (isDisposed != 1) continue; // Only check disposed buffers

            // Check _buffer field
            var bufferField = obj.Type.GetFieldByName("_buffer");
            if (bufferField == null) continue;

            var bufferObj = bufferField.ReadObject(obj.Address, interior: false);
            if (!bufferObj.IsValid || bufferObj.Type == null) continue;

            var bufferSize = bufferObj.AsArray().Length;
            var buffer = new byte[bufferSize];
            if (runtime.DataTarget.DataReader.Read(bufferObj.Address + (ulong)IntPtr.Size * 2, buffer) == 0)
                continue;

            if (buffer.Any(b => b != 0))
            {
                stillContainsData++;
                violations.Add(new HeapMatch(obj.Address, bufferSize, "SecureBuffer (disposed but not zeroed)"));
            }
            else
            {
                properlyZeroed++;
            }
        }

        return new SecureBufferReport(totalFound, properlyZeroed, stillContainsData, violations);
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
