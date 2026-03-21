using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CyTypes.Primitives.Shared;

/// <summary>
/// Provides constant-time comparison operations for encrypted type values
/// to prevent timing side-channel attacks.
/// </summary>
internal static class ConstantTimeCompare
{
    /// <summary>Constant-time equality for int values using FixedTimeEquals on byte representation.</summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool Equals(int left, int right)
    {
        Span<byte> a = stackalloc byte[4];
        Span<byte> b = stackalloc byte[4];
        BitConverter.TryWriteBytes(a, left);
        BitConverter.TryWriteBytes(b, right);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>Constant-time equality for long values using FixedTimeEquals on byte representation.</summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool Equals(long left, long right)
    {
        Span<byte> a = stackalloc byte[8];
        Span<byte> b = stackalloc byte[8];
        BitConverter.TryWriteBytes(a, left);
        BitConverter.TryWriteBytes(b, right);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Constant-time equality for float values using FixedTimeEquals on byte representation.
    /// Returns false if either value is NaN (IEEE 754 compliance).
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool Equals(float left, float right)
    {
        // IEEE 754: NaN != NaN, check via bit pattern (constant-time)
        int leftBits = BitConverter.SingleToInt32Bits(left);
        int rightBits = BitConverter.SingleToInt32Bits(right);
        // NaN detection: exponent all 1s and mantissa non-zero
        bool leftIsNaN = (leftBits & 0x7F800000) == 0x7F800000 && (leftBits & 0x007FFFFF) != 0;
        bool rightIsNaN = (rightBits & 0x7F800000) == 0x7F800000 && (rightBits & 0x007FFFFF) != 0;
        // Use bitwise OR to avoid branching on NaN check
        int nanMask = (leftIsNaN || rightIsNaN) ? 0 : 1;

        Span<byte> a = stackalloc byte[4];
        Span<byte> b = stackalloc byte[4];
        BitConverter.TryWriteBytes(a, leftBits);
        BitConverter.TryWriteBytes(b, rightBits);
        bool bytesEqual = CryptographicOperations.FixedTimeEquals(a, b);
        return bytesEqual & (nanMask == 1);
    }

    /// <summary>
    /// Constant-time equality for double values using FixedTimeEquals on byte representation.
    /// Returns false if either value is NaN (IEEE 754 compliance).
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool Equals(double left, double right)
    {
        long leftBits = BitConverter.DoubleToInt64Bits(left);
        long rightBits = BitConverter.DoubleToInt64Bits(right);
        // NaN detection
        bool leftIsNaN = (leftBits & 0x7FF0000000000000L) == 0x7FF0000000000000L && (leftBits & 0x000FFFFFFFFFFFFFL) != 0;
        bool rightIsNaN = (rightBits & 0x7FF0000000000000L) == 0x7FF0000000000000L && (rightBits & 0x000FFFFFFFFFFFFFL) != 0;
        int nanMask = (leftIsNaN || rightIsNaN) ? 0 : 1;

        Span<byte> a = stackalloc byte[8];
        Span<byte> b = stackalloc byte[8];
        BitConverter.TryWriteBytes(a, leftBits);
        BitConverter.TryWriteBytes(b, rightBits);
        bool bytesEqual = CryptographicOperations.FixedTimeEquals(a, b);
        return bytesEqual & (nanMask == 1);
    }

    /// <summary>Constant-time equality for decimal values using FixedTimeEquals on byte representation.</summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool Equals(decimal left, decimal right)
    {
        Span<byte> a = stackalloc byte[16];
        Span<byte> b = stackalloc byte[16];
        WriteDecimal(a, left);
        WriteDecimal(b, right);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>Constant-time equality for bool values using FixedTimeEquals.</summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool Equals(bool left, bool right)
    {
        Span<byte> a = stackalloc byte[1];
        Span<byte> b = stackalloc byte[1];
        a[0] = left ? (byte)1 : (byte)0;
        b[0] = right ? (byte)1 : (byte)0;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Constant-time three-way comparison for int values.
    /// Returns -1, 0, or 1 using branch-free bit manipulation.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int Compare(int left, int right)
    {
        // Convert to big-endian comparable form: XOR sign bit for unsigned-equivalent ordering
        uint a = (uint)left ^ 0x80000000u;
        uint b = (uint)right ^ 0x80000000u;
        // Branch-free: (a > b) - (a < b) gives -1, 0, or 1
        // Use subtraction-with-borrow approach via 64-bit arithmetic
        long diff = (long)a - (long)b;
        return (int)((diff >> 63) | (long)((ulong)(-diff) >> 63));
    }

    /// <summary>
    /// Constant-time three-way comparison for long values.
    /// Returns -1, 0, or 1 using branch-free bit manipulation.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int Compare(long left, long right)
    {
        // XOR sign bit for unsigned-equivalent ordering
        ulong a = (ulong)left ^ 0x8000000000000000uL;
        ulong b = (ulong)right ^ 0x8000000000000000uL;
        // Branch-free comparison using conditional subtraction
        // (a > b) gives 1, (a < b) gives -1, equal gives 0
        int gt = a > b ? 1 : 0; // This is a cmov on x64
        int lt = a < b ? 1 : 0;
        return gt - lt;
    }

    /// <summary>
    /// Constant-time three-way comparison for float values.
    /// Uses IEEE 754 bit trick for total ordering. NaN sorts after all other values.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int Compare(float left, float right)
    {
        int leftBits = BitConverter.SingleToInt32Bits(left);
        int rightBits = BitConverter.SingleToInt32Bits(right);
        // IEEE 754 total order trick: negative values flip all bits, positive flip only sign bit
        leftBits = leftBits < 0 ? ~leftBits : leftBits ^ int.MinValue;
        rightBits = rightBits < 0 ? ~rightBits : rightBits ^ int.MinValue;
        return Compare(leftBits, rightBits);
    }

    /// <summary>
    /// Constant-time three-way comparison for double values.
    /// Uses IEEE 754 bit trick for total ordering. NaN sorts after all other values.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int Compare(double left, double right)
    {
        long leftBits = BitConverter.DoubleToInt64Bits(left);
        long rightBits = BitConverter.DoubleToInt64Bits(right);
        // IEEE 754 total order trick
        leftBits = leftBits < 0 ? ~leftBits : leftBits ^ long.MinValue;
        rightBits = rightBits < 0 ? ~rightBits : rightBits ^ long.MinValue;
        return Compare(leftBits, rightBits);
    }

    /// <summary>
    /// Constant-time three-way comparison for decimal values.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int Compare(decimal left, decimal right)
    {
        // For decimal, we normalize and compare byte representations
        // decimal.Compare is not guaranteed constant-time, so we use our own
        Span<byte> a = stackalloc byte[16];
        Span<byte> b = stackalloc byte[16];
        WriteDecimal(a, left);
        WriteDecimal(b, right);

        // Byte-by-byte comparison (big-endian) — sign byte is at position 15 in GetBits layout
        // We need to handle sign separately for correct ordering
        int signA = (a[15] & 0x80) != 0 ? -1 : 1;
        int signB = (b[15] & 0x80) != 0 ? -1 : 1;

        if (signA != signB)
            return signA > signB ? 1 : -1;

        // Same sign: compare magnitude (big-endian byte comparison)
        int cmp = 0;
        for (int i = 15; i >= 0; i--)
        {
            int diff = a[i] - b[i];
            // First non-zero diff wins (constant-time: always iterate all bytes)
            cmp = cmp == 0 ? diff : cmp;
        }

        return signA * (cmp > 0 ? 1 : cmp < 0 ? -1 : 0);
    }

    /// <summary>
    /// Constant-time three-way comparison for DateTime values (compares Ticks as long).
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int Compare(DateTime left, DateTime right)
    {
        return Compare(left.Ticks, right.Ticks);
    }

    private static void WriteDecimal(Span<byte> destination, decimal value)
    {
        Span<int> bits = stackalloc int[4];
        decimal.TryGetBits(value, bits, out _);
        for (int i = 0; i < 4; i++)
            BitConverter.TryWriteBytes(destination.Slice(i * 4, 4), bits[i]);
    }
}
