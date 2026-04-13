"""
Low-level ctypes bindings to the CyTypes native library.
"""

import ctypes
import ctypes.util
import os
import platform
import sys
from pathlib import Path


def _find_library() -> ctypes.CDLL:
    """Locate and load the CyTypes shared library."""
    system = platform.system()

    if system == "Linux":
        names = ["libcytypes.so", "cytypes.so"]
    elif system == "Darwin":
        names = ["libcytypes.dylib", "cytypes.dylib"]
    elif system == "Windows":
        names = ["cytypes.dll", "libcytypes.dll"]
    else:
        names = ["libcytypes.so"]

    # Search order: CYTYPES_LIB_PATH env var, package directory, system paths
    search_dirs = []

    env_path = os.environ.get("CYTYPES_LIB_PATH")
    if env_path:
        search_dirs.append(Path(env_path))

    search_dirs.append(Path(__file__).parent)
    search_dirs.append(Path(__file__).parent / "lib")

    for d in search_dirs:
        for name in names:
            path = d / name
            if path.exists():
                return ctypes.CDLL(str(path))

    # Fall back to system library search
    found = ctypes.util.find_library("cytypes")
    if found:
        return ctypes.CDLL(found)

    raise OSError(
        f"Could not find CyTypes native library. "
        f"Set CYTYPES_LIB_PATH to the directory containing the shared library, "
        f"or install it to a system library path. "
        f"Searched: {[str(d) for d in search_dirs]}"
    )


_lib = _find_library()

# ── Function signatures ────────────────────────────────────────────────

_lib.cytypes_init.restype = ctypes.c_int
_lib.cytypes_init.argtypes = []

_lib.cytypes_shutdown.restype = None
_lib.cytypes_shutdown.argtypes = []

_lib.cytypes_handle_count.restype = ctypes.c_int
_lib.cytypes_handle_count.argtypes = []

_lib.cytypes_last_error.restype = ctypes.c_int
_lib.cytypes_last_error.argtypes = [ctypes.c_char_p, ctypes.c_int]

# CyInt
_lib.cyint_create.restype = ctypes.c_int64
_lib.cyint_create.argtypes = [ctypes.c_int32]

_lib.cyint_get.restype = ctypes.c_int32
_lib.cyint_get.argtypes = [ctypes.c_int64]

_lib.cyint_add.restype = ctypes.c_int64
_lib.cyint_add.argtypes = [ctypes.c_int64, ctypes.c_int64]

_lib.cyint_sub.restype = ctypes.c_int64
_lib.cyint_sub.argtypes = [ctypes.c_int64, ctypes.c_int64]

_lib.cyint_mul.restype = ctypes.c_int64
_lib.cyint_mul.argtypes = [ctypes.c_int64, ctypes.c_int64]

_lib.cyint_destroy.restype = ctypes.c_int
_lib.cyint_destroy.argtypes = [ctypes.c_int64]

# CyString
_lib.cystring_create.restype = ctypes.c_int64
_lib.cystring_create.argtypes = [ctypes.c_char_p]

_lib.cystring_get.restype = ctypes.c_int
_lib.cystring_get.argtypes = [ctypes.c_int64, ctypes.c_char_p, ctypes.c_int]

_lib.cystring_length.restype = ctypes.c_int
_lib.cystring_length.argtypes = [ctypes.c_int64]

_lib.cystring_destroy.restype = ctypes.c_int
_lib.cystring_destroy.argtypes = [ctypes.c_int64]

# CyBool
_lib.cybool_create.restype = ctypes.c_int64
_lib.cybool_create.argtypes = [ctypes.c_int]

_lib.cybool_get.restype = ctypes.c_int
_lib.cybool_get.argtypes = [ctypes.c_int64]

_lib.cybool_destroy.restype = ctypes.c_int
_lib.cybool_destroy.argtypes = [ctypes.c_int64]

# CyLong
_lib.cylong_create.restype = ctypes.c_int64
_lib.cylong_create.argtypes = [ctypes.c_int64]

_lib.cylong_get.restype = ctypes.c_int64
_lib.cylong_get.argtypes = [ctypes.c_int64]

_lib.cylong_destroy.restype = ctypes.c_int
_lib.cylong_destroy.argtypes = [ctypes.c_int64]

# CyDouble
_lib.cydouble_create.restype = ctypes.c_int64
_lib.cydouble_create.argtypes = [ctypes.c_double]

_lib.cydouble_get.restype = ctypes.c_double
_lib.cydouble_get.argtypes = [ctypes.c_int64]

_lib.cydouble_destroy.restype = ctypes.c_int
_lib.cydouble_destroy.argtypes = [ctypes.c_int64]

# CyBytes
_lib.cybytes_create.restype = ctypes.c_int64
_lib.cybytes_create.argtypes = [ctypes.c_char_p, ctypes.c_int]

_lib.cybytes_get.restype = ctypes.c_int
_lib.cybytes_get.argtypes = [ctypes.c_int64, ctypes.c_char_p, ctypes.c_int]

_lib.cybytes_destroy.restype = ctypes.c_int
_lib.cybytes_destroy.argtypes = [ctypes.c_int64]


# ── Helper ──────────────────────────────────────────────────────────────

def _check_error(handle_or_code: int, context: str = ""):
    """Raise an exception if the native call returned an error."""
    if handle_or_code < 0:
        buf = ctypes.create_string_buffer(1024)
        n = _lib.cytypes_last_error(buf, 1024)
        msg = buf.value.decode("utf-8") if n > 0 else "Unknown error"
        raise RuntimeError(f"CyTypes error{f' in {context}' if context else ''}: {msg}")


def init():
    """Initialize the CyTypes runtime."""
    rc = _lib.cytypes_init()
    _check_error(rc, "init")


def shutdown():
    """Shut down the CyTypes runtime and release all handles."""
    _lib.cytypes_shutdown()


# ── Pythonic wrappers ───────────────────────────────────────────────────

class CyInt:
    """Encrypted 32-bit integer (AES-256-GCM in memory)."""

    __slots__ = ("_handle",)

    def __init__(self, value: int):
        self._handle = _lib.cyint_create(ctypes.c_int32(value))
        _check_error(self._handle, "CyInt.create")

    @classmethod
    def _from_handle(cls, handle: int) -> "CyInt":
        obj = object.__new__(cls)
        obj._handle = handle
        return obj

    @property
    def value(self) -> int:
        """Decrypt and return the plaintext value. Marks as compromised."""
        return _lib.cyint_get(self._handle)

    def __add__(self, other: "CyInt") -> "CyInt":
        h = _lib.cyint_add(self._handle, other._handle)
        _check_error(h, "CyInt.add")
        return CyInt._from_handle(h)

    def __sub__(self, other: "CyInt") -> "CyInt":
        h = _lib.cyint_sub(self._handle, other._handle)
        _check_error(h, "CyInt.sub")
        return CyInt._from_handle(h)

    def __mul__(self, other: "CyInt") -> "CyInt":
        h = _lib.cyint_mul(self._handle, other._handle)
        _check_error(h, "CyInt.mul")
        return CyInt._from_handle(h)

    def __repr__(self) -> str:
        return f"CyInt(<encrypted>)"

    def __del__(self):
        if hasattr(self, "_handle") and self._handle >= 0:
            _lib.cyint_destroy(self._handle)


class CyString:
    """Encrypted UTF-8 string (AES-256-GCM in memory)."""

    __slots__ = ("_handle",)

    def __init__(self, value: str):
        encoded = value.encode("utf-8")
        self._handle = _lib.cystring_create(encoded)
        _check_error(self._handle, "CyString.create")

    @property
    def value(self) -> str:
        """Decrypt and return the plaintext string. Marks as compromised."""
        size = _lib.cystring_get(self._handle, None, 0)
        if size < 0:
            _check_error(size, "CyString.get")
        buf = ctypes.create_string_buffer(size)
        _lib.cystring_get(self._handle, buf, size)
        return buf.value.decode("utf-8")

    def __len__(self) -> int:
        return _lib.cystring_length(self._handle)

    def __repr__(self) -> str:
        return f"CyString(<encrypted, len={len(self)}>)"

    def __del__(self):
        if hasattr(self, "_handle") and self._handle >= 0:
            _lib.cystring_destroy(self._handle)


class CyBool:
    """Encrypted boolean (AES-256-GCM in memory)."""

    __slots__ = ("_handle",)

    def __init__(self, value: bool):
        self._handle = _lib.cybool_create(1 if value else 0)
        _check_error(self._handle, "CyBool.create")

    @property
    def value(self) -> bool:
        """Decrypt and return the plaintext boolean. Marks as compromised."""
        return _lib.cybool_get(self._handle) == 1

    def __bool__(self) -> bool:
        return self.value

    def __repr__(self) -> str:
        return f"CyBool(<encrypted>)"

    def __del__(self):
        if hasattr(self, "_handle") and self._handle >= 0:
            _lib.cybool_destroy(self._handle)


class CyLong:
    """Encrypted 64-bit integer (AES-256-GCM in memory)."""

    __slots__ = ("_handle",)

    def __init__(self, value: int):
        self._handle = _lib.cylong_create(ctypes.c_int64(value))
        _check_error(self._handle, "CyLong.create")

    @property
    def value(self) -> int:
        return _lib.cylong_get(self._handle)

    def __repr__(self) -> str:
        return f"CyLong(<encrypted>)"

    def __del__(self):
        if hasattr(self, "_handle") and self._handle >= 0:
            _lib.cylong_destroy(self._handle)


class CyDouble:
    """Encrypted 64-bit float (AES-256-GCM in memory)."""

    __slots__ = ("_handle",)

    def __init__(self, value: float):
        self._handle = _lib.cydouble_create(ctypes.c_double(value))
        _check_error(self._handle, "CyDouble.create")

    @property
    def value(self) -> float:
        return _lib.cydouble_get(self._handle)

    def __repr__(self) -> str:
        return f"CyDouble(<encrypted>)"

    def __del__(self):
        if hasattr(self, "_handle") and self._handle >= 0:
            _lib.cydouble_destroy(self._handle)


class CyBytes:
    """Encrypted byte array (AES-256-GCM in memory)."""

    __slots__ = ("_handle",)

    def __init__(self, value: bytes):
        self._handle = _lib.cybytes_create(value, len(value))
        _check_error(self._handle, "CyBytes.create")

    @property
    def value(self) -> bytes:
        size = _lib.cybytes_get(self._handle, None, 0)
        if size < 0:
            _check_error(size, "CyBytes.get")
        buf = ctypes.create_string_buffer(size)
        _lib.cybytes_get(self._handle, buf, size)
        return buf.raw[:size]

    def __len__(self) -> int:
        return _lib.cybytes_get(self._handle, None, 0)

    def __repr__(self) -> str:
        return f"CyBytes(<encrypted, len={len(self)}>)"

    def __del__(self):
        if hasattr(self, "_handle") and self._handle >= 0:
            _lib.cybytes_destroy(self._handle)
