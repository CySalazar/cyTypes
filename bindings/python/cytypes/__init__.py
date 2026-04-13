"""
CyTypes — Always-encrypted primitive types.
Python bindings for the CyTypes native library (libcytypes.so / cytypes.dll).

Usage:
    from cytypes import CyInt, CyString, CyBool

    x = CyInt(42)
    y = CyInt(8)
    z = x + y
    print(z.value)  # 50

    s = CyString("sensitive data")
    print(s.value)   # "sensitive data"
    print(len(s))    # 14
"""

from cytypes._core import (
    CyInt,
    CyString,
    CyBool,
    CyLong,
    CyDouble,
    CyBytes,
    init,
    shutdown,
)

__version__ = "0.1.0"
__all__ = ["CyInt", "CyString", "CyBool", "CyLong", "CyDouble", "CyBytes", "init", "shutdown"]

# Auto-initialize the runtime on import
init()

import atexit
atexit.register(shutdown)
