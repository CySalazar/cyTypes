using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace CyTypes.Core.KeyManagement;

/// <summary>
/// Abstraction for platform-specific secure key storage.
/// </summary>
public interface IPlatformKeyStore
{
    /// <summary>
    /// Gets the protection capability level of this key store.
    /// </summary>
    KeyStoreCapability Capability { get; }

    /// <summary>
    /// Attempts to store key data under the specified name.
    /// </summary>
    /// <param name="keyName">The name to associate with the key.</param>
    /// <param name="keyData">The raw key bytes to store.</param>
    /// <returns><see langword="true"/> if the key was stored successfully.</returns>
    bool TryStore(string keyName, ReadOnlySpan<byte> keyData);

    /// <summary>
    /// Attempts to retrieve key data by name.
    /// </summary>
    /// <param name="keyName">The name of the key to retrieve.</param>
    /// <returns>The key bytes, or <see langword="null"/> if not found.</returns>
    byte[]? TryRetrieve(string keyName);

    /// <summary>
    /// Attempts to delete a stored key by name.
    /// </summary>
    /// <param name="keyName">The name of the key to delete.</param>
    /// <returns><see langword="true"/> if the key was deleted or did not exist.</returns>
    bool TryDelete(string keyName);
}

/// <summary>
/// Factory that creates the appropriate <see cref="IPlatformKeyStore"/> for the current OS.
/// </summary>
public static class PlatformKeyStoreFactory
{
    /// <summary>
    /// Creates a platform-appropriate key store, verifying it meets the minimum capability requirement.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <param name="minimumCapability">The minimum acceptable protection level.</param>
    /// <returns>An <see cref="IPlatformKeyStore"/> instance for the current platform.</returns>
    public static IPlatformKeyStore Create(ILogger? logger = null, KeyStoreCapability minimumCapability = KeyStoreCapability.InMemoryOnly)
    {
        IPlatformKeyStore store;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            store = new MacOsKeyStore(logger);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            store = new WindowsKeyStore(logger);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            var linux = new LinuxKeyStore(logger);
            if (linux.IsAvailable)
            {
                store = linux;
            }
            else
            {
                logger?.LogWarning("libsecret not available on this Linux system; falling back to in-memory store.");
                store = new InMemoryKeyStore();
            }
        }
        else
        {
            logger?.LogWarning("No platform key store available; falling back to in-memory store.");
            store = new InMemoryKeyStore();
        }

        if (store.Capability > minimumCapability)
        {
            throw new SecurityException(
                $"Platform key store capability '{store.Capability}' does not meet minimum requirement '{minimumCapability}'. " +
                "Reduce KeyStoreMinimumCapability or use a platform with stronger key protection.");
        }

        if (store is InMemoryKeyStore)
        {
            logger?.LogWarning(
                "CyTypes is using an in-memory key store (Capability={Capability}). Keys are NOT protected by the OS.",
                store.Capability);
        }

        return store;
    }
}

/// <summary>
/// In-memory key store with no OS-level protection. Used as a fallback when no platform store is available.
/// </summary>
public sealed class InMemoryKeyStore : IPlatformKeyStore
{
    /// <inheritdoc/>
    public KeyStoreCapability Capability => KeyStoreCapability.InMemoryOnly;
    private readonly Dictionary<string, byte[]> _store = new();
    private readonly object _lock = new();

    /// <inheritdoc/>
    public bool TryStore(string keyName, ReadOnlySpan<byte> keyData)
    {
        lock (_lock)
        {
            _store[keyName] = keyData.ToArray();
            return true;
        }
    }

    /// <inheritdoc/>
    public byte[]? TryRetrieve(string keyName)
    {
        lock (_lock)
        {
            return _store.TryGetValue(keyName, out var data) ? data.ToArray() : null;
        }
    }

    /// <inheritdoc/>
    public bool TryDelete(string keyName)
    {
        lock (_lock)
        {
            if (_store.Remove(keyName, out var data))
            {
                CryptographicOperations.ZeroMemory(data);
                return true;
            }
            return false;
        }
    }
}

internal sealed class MacOsKeyStore : IPlatformKeyStore
{
    public KeyStoreCapability Capability => KeyStoreCapability.HardwareBacked;
    private readonly ILogger? _logger;
    private const string ServiceName = "CyTypes";
    private const int ErrSecSuccess = 0;
    private const int ErrSecItemNotFound = -25300;
    private const int ErrSecDuplicateItem = -25299;

    public MacOsKeyStore(ILogger? logger) => _logger = logger;

    public bool TryStore(string keyName, ReadOnlySpan<byte> keyData)
    {
        // Delete existing entry first
        TryDelete(keyName);

        var serviceData = System.Text.Encoding.UTF8.GetBytes(ServiceName);
        var accountData = System.Text.Encoding.UTF8.GetBytes(keyName);
        var valueData = keyData.ToArray();

        try
        {
            var dict = CoreFoundation.CFDictionaryCreateMutable(IntPtr.Zero, 4,
                IntPtr.Zero, IntPtr.Zero);

            using var classRef = new CfTypeRef(Security.kSecClassGenericPassword);
            using var serviceRef = new CfTypeRef(CoreFoundation.CFDataCreate(serviceData));
            using var accountRef = new CfTypeRef(CoreFoundation.CFDataCreate(accountData));
            using var valueRef = new CfTypeRef(CoreFoundation.CFDataCreate(valueData));

            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecClass, Security.kSecClassGenericPassword);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecAttrService, serviceRef.Handle);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecAttrAccount, accountRef.Handle);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecValueData, valueRef.Handle);

            var status = Security.SecItemAdd(dict, out _);
            CoreFoundation.CFRelease(dict);

            CryptographicOperations.ZeroMemory(valueData);

            if (status == ErrSecSuccess)
                return true;

            _logger?.LogWarning("macOS Keychain SecItemAdd failed with status {Status}", status);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "macOS Keychain store failed, falling back");
            return false;
        }
    }

    public byte[]? TryRetrieve(string keyName)
    {
        var serviceData = System.Text.Encoding.UTF8.GetBytes(ServiceName);
        var accountData = System.Text.Encoding.UTF8.GetBytes(keyName);

        try
        {
            var dict = CoreFoundation.CFDictionaryCreateMutable(IntPtr.Zero, 5,
                IntPtr.Zero, IntPtr.Zero);

            using var serviceRef = new CfTypeRef(CoreFoundation.CFDataCreate(serviceData));
            using var accountRef = new CfTypeRef(CoreFoundation.CFDataCreate(accountData));

            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecClass, Security.kSecClassGenericPassword);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecAttrService, serviceRef.Handle);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecAttrAccount, accountRef.Handle);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecReturnData, CoreFoundation.kCFBooleanTrue);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecMatchLimit, Security.kSecMatchLimitOne);

            var status = Security.SecItemCopyMatching(dict, out var result);
            CoreFoundation.CFRelease(dict);

            if (status != ErrSecSuccess || result == IntPtr.Zero)
            {
                if (status != ErrSecItemNotFound)
                    _logger?.LogWarning("macOS Keychain SecItemCopyMatching failed with status {Status}", status);
                return null;
            }

            try
            {
                var length = (int)CoreFoundation.CFDataGetLength(result);
                var ptr = CoreFoundation.CFDataGetBytePtr(result);
                var data = new byte[length];
                Marshal.Copy(ptr, data, 0, length);
                return data;
            }
            finally
            {
                CoreFoundation.CFRelease(result);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "macOS Keychain retrieve failed");
            return null;
        }
    }

    public bool TryDelete(string keyName)
    {
        var serviceData = System.Text.Encoding.UTF8.GetBytes(ServiceName);
        var accountData = System.Text.Encoding.UTF8.GetBytes(keyName);

        try
        {
            var dict = CoreFoundation.CFDictionaryCreateMutable(IntPtr.Zero, 3,
                IntPtr.Zero, IntPtr.Zero);

            using var serviceRef = new CfTypeRef(CoreFoundation.CFDataCreate(serviceData));
            using var accountRef = new CfTypeRef(CoreFoundation.CFDataCreate(accountData));

            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecClass, Security.kSecClassGenericPassword);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecAttrService, serviceRef.Handle);
            CoreFoundation.CFDictionaryAddValue(dict, Security.kSecAttrAccount, accountRef.Handle);

            var status = Security.SecItemDelete(dict);
            CoreFoundation.CFRelease(dict);

            if (status == ErrSecSuccess || status == ErrSecItemNotFound)
                return true;

            _logger?.LogWarning("macOS Keychain SecItemDelete failed with status {Status}", status);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "macOS Keychain delete failed");
            return false;
        }
    }
}

internal sealed class WindowsKeyStore : IPlatformKeyStore
{
    public KeyStoreCapability Capability => KeyStoreCapability.OsProtected;
    private readonly ILogger? _logger;
    private readonly InMemoryKeyStore _fallback = new();
    private static readonly byte[] DpapiEntropy = "CyTypes.KeyStore.v1"u8.ToArray();

    public WindowsKeyStore(ILogger? logger) => _logger = logger;

    public bool TryStore(string keyName, ReadOnlySpan<byte> keyData)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _logger?.LogDebug("Not on Windows; using in-memory fallback for {KeyName}", keyName);
            return _fallback.TryStore(keyName, keyData);
        }

        try
        {
            var plaintext = keyData.ToArray();
            try
            {
                var protectedBytes = System.Security.Cryptography.ProtectedData.Protect(
                    plaintext, DpapiEntropy, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return _fallback.TryStore(keyName, protectedBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "DPAPI Protect failed for {KeyName}; using in-memory fallback", keyName);
            return _fallback.TryStore(keyName, keyData);
        }
    }

    public byte[]? TryRetrieve(string keyName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return _fallback.TryRetrieve(keyName);

        var protectedBytes = _fallback.TryRetrieve(keyName);
        if (protectedBytes is null)
            return null;

        try
        {
            var plaintext = System.Security.Cryptography.ProtectedData.Unprotect(
                protectedBytes, DpapiEntropy, System.Security.Cryptography.DataProtectionScope.CurrentUser);
            return plaintext;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "DPAPI Unprotect failed for {KeyName}", keyName);
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public bool TryDelete(string keyName) => _fallback.TryDelete(keyName);
}

internal sealed class LinuxKeyStore : IPlatformKeyStore
{
    public KeyStoreCapability Capability => KeyStoreCapability.OsProtected;
    private readonly ILogger? _logger;
    private const string ServiceName = "CyTypes";
    private static readonly IntPtr SchemaPtr;

    public bool IsAvailable { get; }

    static LinuxKeyStore()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return;

        try
        {
            SchemaPtr = LibSecret.secret_schema_new(
                ServiceName, LibSecret.SECRET_SCHEMA_NONE,
                "key_name", LibSecret.SECRET_SCHEMA_ATTRIBUTE_STRING,
                IntPtr.Zero);
        }
        catch
        {
            SchemaPtr = IntPtr.Zero;
        }
    }

    public LinuxKeyStore(ILogger? logger)
    {
        _logger = logger;
        IsAvailable = SchemaPtr != IntPtr.Zero && LibSecret.IsLoaded;
    }

    public bool TryStore(string keyName, ReadOnlySpan<byte> keyData)
    {
        if (!IsAvailable) return false;

        try
        {
            var base64 = Convert.ToBase64String(keyData);
            var label = $"{ServiceName}:{keyName}";
            var success = LibSecret.secret_password_store_sync(
                SchemaPtr,
                LibSecret.SECRET_COLLECTION_DEFAULT,
                label,
                base64,
                IntPtr.Zero, // cancellable
                out var error,
                "key_name", keyName,
                IntPtr.Zero);

            if (error != IntPtr.Zero)
            {
                var errorMsg = LibSecret.GetErrorMessage(error);
                LibSecret.g_error_free(error);
                _logger?.LogWarning("libsecret store failed for {KeyName}: {Error}", keyName, errorMsg);
                return false;
            }

            return success;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "libsecret store failed for {KeyName}", keyName);
            return false;
        }
    }

    public byte[]? TryRetrieve(string keyName)
    {
        if (!IsAvailable) return null;

        try
        {
            var password = LibSecret.secret_password_lookup_sync(
                SchemaPtr,
                IntPtr.Zero, // cancellable
                out var error,
                "key_name", keyName,
                IntPtr.Zero);

            if (error != IntPtr.Zero)
            {
                var errorMsg = LibSecret.GetErrorMessage(error);
                LibSecret.g_error_free(error);
                _logger?.LogWarning("libsecret lookup failed for {KeyName}: {Error}", keyName, errorMsg);
                return null;
            }

            if (password == IntPtr.Zero)
                return null;

            var base64 = Marshal.PtrToStringAnsi(password);
            LibSecret.secret_password_free(password);

            return base64 is null ? null : Convert.FromBase64String(base64);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "libsecret lookup failed for {KeyName}", keyName);
            return null;
        }
    }

    public bool TryDelete(string keyName)
    {
        if (!IsAvailable) return false;

        try
        {
            var success = LibSecret.secret_password_clear_sync(
                SchemaPtr,
                IntPtr.Zero, // cancellable
                out var error,
                "key_name", keyName,
                IntPtr.Zero);

            if (error != IntPtr.Zero)
            {
                var errorMsg = LibSecret.GetErrorMessage(error);
                LibSecret.g_error_free(error);
                _logger?.LogWarning("libsecret clear failed for {KeyName}: {Error}", keyName, errorMsg);
                return false;
            }

            return success;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "libsecret clear failed for {KeyName}", keyName);
            return false;
        }
    }
}

internal static class LibSecret
{
    private const string Lib = "libsecret-1.so.0";

    public const int SECRET_SCHEMA_NONE = 0;
    public const int SECRET_SCHEMA_ATTRIBUTE_STRING = 0;
    public static readonly IntPtr SECRET_COLLECTION_DEFAULT = IntPtr.Zero;

    public static bool IsLoaded { get; }

    static LibSecret()
    {
        try
        {
            IsLoaded = NativeLibrary.TryLoad(Lib, out _);
        }
        catch
        {
            IsLoaded = false;
        }
    }

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    public static extern IntPtr secret_schema_new(
        string name, int flags,
        string attribute1Name, int attribute1Type,
        IntPtr terminator);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    public static extern bool secret_password_store_sync(
        IntPtr schema, IntPtr collection,
        string label, string password,
        IntPtr cancellable, out IntPtr error,
        string attr1Name, string attr1Value,
        IntPtr terminator);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    public static extern IntPtr secret_password_lookup_sync(
        IntPtr schema,
        IntPtr cancellable, out IntPtr error,
        string attr1Name, string attr1Value,
        IntPtr terminator);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    public static extern bool secret_password_clear_sync(
        IntPtr schema,
        IntPtr cancellable, out IntPtr error,
        string attr1Name, string attr1Value,
        IntPtr terminator);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void secret_password_free(IntPtr password);

    [DllImport("libglib-2.0.so.0", CallingConvention = CallingConvention.Cdecl)]
    public static extern void g_error_free(IntPtr error);

    public static string GetErrorMessage(IntPtr error)
    {
        if (error == IntPtr.Zero) return string.Empty;
        // GError struct: domain (uint32), code (int), message (char*)
        var messagePtr = Marshal.ReadIntPtr(error, IntPtr.Size);
        return Marshal.PtrToStringAnsi(messagePtr) ?? "Unknown error";
    }
}

// Minimal CoreFoundation/Security P/Invoke for macOS
internal static class Security
{
    private const string SecurityFramework = "/System/Library/Frameworks/Security.framework/Security";

    public static readonly IntPtr kSecClass;
    public static readonly IntPtr kSecClassGenericPassword;
    public static readonly IntPtr kSecAttrService;
    public static readonly IntPtr kSecAttrAccount;
    public static readonly IntPtr kSecValueData;
    public static readonly IntPtr kSecReturnData;
    public static readonly IntPtr kSecMatchLimit;
    public static readonly IntPtr kSecMatchLimitOne;

    static Security()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return;

        var lib = NativeLibrary.Load(SecurityFramework);
        kSecClass = GetGlobalCfString(lib, "kSecClass");
        kSecClassGenericPassword = GetGlobalCfString(lib, "kSecClassGenericPassword");
        kSecAttrService = GetGlobalCfString(lib, "kSecAttrService");
        kSecAttrAccount = GetGlobalCfString(lib, "kSecAttrAccount");
        kSecValueData = GetGlobalCfString(lib, "kSecValueData");
        kSecReturnData = GetGlobalCfString(lib, "kSecReturnData");
        kSecMatchLimit = GetGlobalCfString(lib, "kSecMatchLimit");
        kSecMatchLimitOne = GetGlobalCfString(lib, "kSecMatchLimitOne");
    }

    private static IntPtr GetGlobalCfString(IntPtr lib, string symbol)
    {
        var ptr = NativeLibrary.GetExport(lib, symbol);
        return Marshal.ReadIntPtr(ptr);
    }

    [DllImport(SecurityFramework)]
    public static extern int SecItemAdd(IntPtr attributes, out IntPtr result);

    [DllImport(SecurityFramework)]
    public static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

    [DllImport(SecurityFramework)]
    public static extern int SecItemDelete(IntPtr query);
}

internal static class CoreFoundation
{
    private const string CF = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    public static readonly IntPtr kCFBooleanTrue;

    static CoreFoundation()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return;

        var lib = NativeLibrary.Load(CF);
        var ptr = NativeLibrary.GetExport(lib, "kCFBooleanTrue");
        kCFBooleanTrue = Marshal.ReadIntPtr(ptr);
    }

    [DllImport(CF)]
    public static extern IntPtr CFDictionaryCreateMutable(IntPtr allocator, nint capacity,
        IntPtr keyCallBacks, IntPtr valueCallBacks);

    [DllImport(CF)]
    public static extern void CFDictionaryAddValue(IntPtr dict, IntPtr key, IntPtr value);

    [DllImport(CF)]
    public static extern void CFRelease(IntPtr obj);

    [DllImport(CF)]
    public static extern IntPtr CFDataGetBytePtr(IntPtr data);

    [DllImport(CF)]
    public static extern nint CFDataGetLength(IntPtr data);

    public static IntPtr CFDataCreate(byte[] data)
    {
        return CFDataCreateWithBytes(IntPtr.Zero, data, data.Length);
    }

    [DllImport(CF, EntryPoint = "CFDataCreate")]
    private static extern IntPtr CFDataCreateWithBytes(IntPtr allocator, byte[] bytes, nint length);
}

internal readonly struct CfTypeRef : IDisposable
{
    public IntPtr Handle { get; }
    public CfTypeRef(IntPtr handle) => Handle = handle;
    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
            CoreFoundation.CFRelease(Handle);
    }
}
