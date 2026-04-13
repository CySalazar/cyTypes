using System.Runtime.InteropServices;
using System.Text;
using CyTypes.Primitives;

namespace CyTypes.NativeExport;

/// <summary>
/// C ABI facade for CyTypes primitives.
/// All functions use [UnmanagedCallersOnly] to export with C linkage.
/// Handle-based API: callers receive opaque int64 handles and must call
/// the corresponding _destroy function to release resources.
///
/// Error handling: functions return 0 on success, negative on error.
/// Call cytypes_last_error() to retrieve the error message.
///
/// Thread safety: all functions are thread-safe. Each handle is independently
/// managed and can be used from any thread.
/// </summary>
public static partial class NativeApi
{
    // ═══════════════════════════════════════════════════════════════════
    // Lifecycle
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// Initializes the CyTypes runtime. Must be called before any other function.
    /// Returns 0 on success, -1 on error.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "cytypes_init")]
    public static int Init()
    {
        try
        {
            ErrorState.Clear();
            return 0;
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>
    /// Shuts down the CyTypes runtime and releases all handles.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "cytypes_shutdown")]
    public static void Shutdown()
    {
        HandleTable.Clear();
    }

    /// <summary>
    /// Returns the number of live handles (for diagnostics/leak detection).
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "cytypes_handle_count")]
    public static int HandleCount()
    {
        return HandleTable.Count;
    }

    /// <summary>
    /// Copies the last error message into the provided buffer.
    /// Returns the number of bytes written, or -1 if no error is set.
    /// If buf is null, returns the required buffer size.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "cytypes_last_error")]
    public static unsafe int LastError(byte* buf, int bufLen)
    {
        var msg = ErrorState.Get();
        if (msg is null) return -1;

        var bytes = Encoding.UTF8.GetBytes(msg);
        if (buf == null) return bytes.Length + 1;

        var toCopy = Math.Min(bytes.Length, bufLen - 1);
        Marshal.Copy(bytes, 0, (nint)buf, toCopy);
        buf[toCopy] = 0; // null terminator
        return toCopy;
    }

    // ═══════════════════════════════════════════════════════════════════
    // CyInt
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>Creates a new CyInt from a plaintext value. Returns a handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cyint_create")]
    public static long CyIntCreate(int value)
    {
        try
        {
            ErrorState.Clear();
            var cyInt = new CyInt(value);
            return HandleTable.Allocate(cyInt);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Decrypts and returns the plaintext value. Marks the instance as compromised.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cyint_get")]
    public static int CyIntGet(long handle)
    {
        try
        {
            ErrorState.Clear();
            var cyInt = HandleTable.Get<CyInt>(handle);
            if (cyInt is null)
            {
                ErrorState.Set("Invalid handle");
                return 0;
            }
            return cyInt.ToInsecureInt();
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return 0;
        }
    }

    /// <summary>Adds two CyInt values. Returns a handle to the result.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cyint_add")]
    public static long CyIntAdd(long handleA, long handleB)
    {
        try
        {
            ErrorState.Clear();
            var a = HandleTable.Get<CyInt>(handleA);
            var b = HandleTable.Get<CyInt>(handleB);
            if (a is null || b is null)
            {
                ErrorState.Set("Invalid handle");
                return -1;
            }
            var result = a + b;
            return HandleTable.Allocate(result);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Subtracts two CyInt values. Returns a handle to the result.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cyint_sub")]
    public static long CyIntSub(long handleA, long handleB)
    {
        try
        {
            ErrorState.Clear();
            var a = HandleTable.Get<CyInt>(handleA);
            var b = HandleTable.Get<CyInt>(handleB);
            if (a is null || b is null)
            {
                ErrorState.Set("Invalid handle");
                return -1;
            }
            var result = a - b;
            return HandleTable.Allocate(result);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Multiplies two CyInt values. Returns a handle to the result.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cyint_mul")]
    public static long CyIntMul(long handleA, long handleB)
    {
        try
        {
            ErrorState.Clear();
            var a = HandleTable.Get<CyInt>(handleA);
            var b = HandleTable.Get<CyInt>(handleB);
            if (a is null || b is null)
            {
                ErrorState.Set("Invalid handle");
                return -1;
            }
            var result = a * b;
            return HandleTable.Allocate(result);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Destroys a CyInt handle and releases its resources.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cyint_destroy")]
    public static int CyIntDestroy(long handle)
    {
        ErrorState.Clear();
        return HandleTable.Free(handle) ? 0 : -1;
    }

    // ═══════════════════════════════════════════════════════════════════
    // CyString
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>Creates a new CyString from a null-terminated UTF-8 string. Returns a handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cystring_create")]
    public static unsafe long CyStringCreate(byte* utf8Value)
    {
        try
        {
            ErrorState.Clear();
            if (utf8Value == null)
            {
                ErrorState.Set("Null pointer");
                return -1;
            }
            var str = Marshal.PtrToStringUTF8((nint)utf8Value);
            if (str is null)
            {
                ErrorState.Set("Invalid UTF-8 string");
                return -1;
            }
            var cyString = new CyString(str);
            return HandleTable.Allocate(cyString);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>
    /// Decrypts the CyString and copies the UTF-8 bytes into the provided buffer.
    /// Returns the number of bytes written (excluding null terminator), or -1 on error.
    /// If buf is null, returns the required buffer size (including null terminator).
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "cystring_get")]
    public static unsafe int CyStringGet(long handle, byte* buf, int bufLen)
    {
        try
        {
            ErrorState.Clear();
            var cyString = HandleTable.Get<CyString>(handle);
            if (cyString is null)
            {
                ErrorState.Set("Invalid handle");
                return -1;
            }
            var str = cyString.ToInsecureString();
            var bytes = Encoding.UTF8.GetBytes(str);

            if (buf == null) return bytes.Length + 1;

            var toCopy = Math.Min(bytes.Length, bufLen - 1);
            Marshal.Copy(bytes, 0, (nint)buf, toCopy);
            buf[toCopy] = 0;
            return toCopy;
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Returns the length of the encrypted string (metadata, no decryption).</summary>
    [UnmanagedCallersOnly(EntryPoint = "cystring_length")]
    public static int CyStringLength(long handle)
    {
        try
        {
            ErrorState.Clear();
            var cyString = HandleTable.Get<CyString>(handle);
            if (cyString is null)
            {
                ErrorState.Set("Invalid handle");
                return -1;
            }
            return cyString.Length;
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Destroys a CyString handle and releases its resources.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cystring_destroy")]
    public static int CyStringDestroy(long handle)
    {
        ErrorState.Clear();
        return HandleTable.Free(handle) ? 0 : -1;
    }

    // ═══════════════════════════════════════════════════════════════════
    // CyBool
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>Creates a new CyBool. Returns a handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cybool_create")]
    public static long CyBoolCreate(int value)
    {
        try
        {
            ErrorState.Clear();
            var cyBool = new CyBool(value != 0);
            return HandleTable.Allocate(cyBool);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Returns 1 for true, 0 for false. Marks instance as compromised.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cybool_get")]
    public static int CyBoolGet(long handle)
    {
        try
        {
            ErrorState.Clear();
            var cyBool = HandleTable.Get<CyBool>(handle);
            if (cyBool is null)
            {
                ErrorState.Set("Invalid handle");
                return -1;
            }
            return cyBool.ToInsecureBool() ? 1 : 0;
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Destroys a CyBool handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cybool_destroy")]
    public static int CyBoolDestroy(long handle)
    {
        ErrorState.Clear();
        return HandleTable.Free(handle) ? 0 : -1;
    }

    // ═══════════════════════════════════════════════════════════════════
    // CyLong
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>Creates a new CyLong. Returns a handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cylong_create")]
    public static long CyLongCreate(long value)
    {
        try
        {
            ErrorState.Clear();
            var cyLong = new CyLong(value);
            return HandleTable.Allocate(cyLong);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Decrypts and returns the plaintext value.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cylong_get")]
    public static long CyLongGet(long handle)
    {
        try
        {
            ErrorState.Clear();
            var cyLong = HandleTable.Get<CyLong>(handle);
            if (cyLong is null)
            {
                ErrorState.Set("Invalid handle");
                return 0;
            }
            return cyLong.ToInsecureLong();
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return 0;
        }
    }

    /// <summary>Destroys a CyLong handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cylong_destroy")]
    public static int CyLongDestroy(long handle)
    {
        ErrorState.Clear();
        return HandleTable.Free(handle) ? 0 : -1;
    }

    // ═══════════════════════════════════════════════════════════════════
    // CyDouble
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>Creates a new CyDouble. Returns a handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cydouble_create")]
    public static long CyDoubleCreate(double value)
    {
        try
        {
            ErrorState.Clear();
            var cyDouble = new CyDouble(value);
            return HandleTable.Allocate(cyDouble);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Decrypts and returns the plaintext value.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cydouble_get")]
    public static double CyDoubleGet(long handle)
    {
        try
        {
            ErrorState.Clear();
            var cyDouble = HandleTable.Get<CyDouble>(handle);
            if (cyDouble is null)
            {
                ErrorState.Set("Invalid handle");
                return 0.0;
            }
            return cyDouble.ToInsecureDouble();
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return 0.0;
        }
    }

    /// <summary>Destroys a CyDouble handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cydouble_destroy")]
    public static int CyDoubleDestroy(long handle)
    {
        ErrorState.Clear();
        return HandleTable.Free(handle) ? 0 : -1;
    }

    // ═══════════════════════════════════════════════════════════════════
    // CyBytes
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>Creates a new CyBytes from a byte array. Returns a handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cybytes_create")]
    public static unsafe long CyBytesCreate(byte* data, int length)
    {
        try
        {
            ErrorState.Clear();
            if (data == null || length <= 0)
            {
                ErrorState.Set("Invalid data or length");
                return -1;
            }
            var bytes = new byte[length];
            Marshal.Copy((nint)data, bytes, 0, length);
            var cyBytes = new CyBytes(bytes);
            return HandleTable.Allocate(cyBytes);
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>
    /// Decrypts CyBytes and copies into the provided buffer.
    /// Returns bytes written, or required size if buf is null.
    /// </summary>
    [UnmanagedCallersOnly(EntryPoint = "cybytes_get")]
    public static unsafe int CyBytesGet(long handle, byte* buf, int bufLen)
    {
        try
        {
            ErrorState.Clear();
            var cyBytes = HandleTable.Get<CyBytes>(handle);
            if (cyBytes is null)
            {
                ErrorState.Set("Invalid handle");
                return -1;
            }
            var bytes = cyBytes.ToInsecureBytes();

            if (buf == null) return bytes.Length;

            var toCopy = Math.Min(bytes.Length, bufLen);
            Marshal.Copy(bytes, 0, (nint)buf, toCopy);
            return toCopy;
        }
        catch (Exception ex)
        {
            ErrorState.Set(ex.Message);
            return -1;
        }
    }

    /// <summary>Destroys a CyBytes handle.</summary>
    [UnmanagedCallersOnly(EntryPoint = "cybytes_destroy")]
    public static int CyBytesDestroy(long handle)
    {
        ErrorState.Clear();
        return HandleTable.Free(handle) ? 0 : -1;
    }
}
