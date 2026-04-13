/*
 * CyTypes Native API — C Header
 * Always-encrypted primitive types via AES-256-GCM.
 *
 * MIT License — Copyright (c) 2026 Matteo Sala
 *
 * Usage:
 *   1. Link against libcytypes.so / cytypes.dll / libcytypes.dylib
 *   2. Call cytypes_init() before any other function
 *   3. Call cytypes_shutdown() before process exit
 *
 * Handle-based API: all cy*_create functions return an opaque int64 handle.
 * You MUST call the corresponding cy*_destroy when done to avoid leaks.
 *
 * Error handling: functions returning int return 0 on success, negative on error.
 * Functions returning handles return -1 on error.
 * Call cytypes_last_error() to get the error message.
 */

#ifndef CYTYPES_H
#define CYTYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Handle type — opaque reference to a managed CyType object */
typedef int64_t cy_handle_t;

/* ── Lifecycle ──────────────────────────────────────────────────────── */

/* Initialize the CyTypes runtime. Must be called first. Returns 0 on success. */
int cytypes_init(void);

/* Shut down the runtime and release all handles. */
void cytypes_shutdown(void);

/* Returns the number of live handles (for leak detection). */
int cytypes_handle_count(void);

/* Copy the last error message into buf (null-terminated UTF-8).
 * Returns bytes written, or required size if buf is NULL, or -1 if no error. */
int cytypes_last_error(char* buf, int buf_len);

/* ── CyInt (encrypted 32-bit integer) ──────────────────────────────── */

cy_handle_t cyint_create(int32_t value);
int32_t     cyint_get(cy_handle_t handle);
cy_handle_t cyint_add(cy_handle_t a, cy_handle_t b);
cy_handle_t cyint_sub(cy_handle_t a, cy_handle_t b);
cy_handle_t cyint_mul(cy_handle_t a, cy_handle_t b);
int         cyint_destroy(cy_handle_t handle);

/* ── CyString (encrypted UTF-8 string) ─────────────────────────────── */

cy_handle_t cystring_create(const char* utf8_value);
int         cystring_get(cy_handle_t handle, char* buf, int buf_len);
int         cystring_length(cy_handle_t handle);
int         cystring_destroy(cy_handle_t handle);

/* ── CyBool (encrypted boolean) ────────────────────────────────────── */

cy_handle_t cybool_create(int value);       /* 0 = false, nonzero = true */
int         cybool_get(cy_handle_t handle); /* returns 1 or 0 */
int         cybool_destroy(cy_handle_t handle);

/* ── CyLong (encrypted 64-bit integer) ─────────────────────────────── */

cy_handle_t cylong_create(int64_t value);
int64_t     cylong_get(cy_handle_t handle);
int         cylong_destroy(cy_handle_t handle);

/* ── CyDouble (encrypted 64-bit float) ─────────────────────────────── */

cy_handle_t cydouble_create(double value);
double      cydouble_get(cy_handle_t handle);
int         cydouble_destroy(cy_handle_t handle);

/* ── CyBytes (encrypted byte array) ───────────────────────────────── */

cy_handle_t cybytes_create(const uint8_t* data, int length);
int         cybytes_get(cy_handle_t handle, uint8_t* buf, int buf_len);
int         cybytes_destroy(cy_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* CYTYPES_H */
