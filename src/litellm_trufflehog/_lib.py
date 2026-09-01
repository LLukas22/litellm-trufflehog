"""ctypes binding to the Go shared library.

The library is a ``-buildmode=c-shared`` build of ``go/cbind``. Loading it with
ctypes rather than building a CPython extension has two concrete benefits:

* One artifact serves every CPython 3.x, because there is no CPython ABI
  involved. No ``cp311``/``cp312``/... wheel matrix.
* ctypes releases the GIL around a foreign call, so scans dispatched to a
  thread pool actually run in parallel instead of serialising.

Every ``char*`` returned by the library is C-allocated and must be released
with ``th_free``. ``_take`` does that, and is the only supported way to read a
returned string: declaring ``restype = c_char_p`` would make ctypes convert to
``bytes`` and discard the pointer, leaking it.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Final

__all__ = [
    "NativeLibraryNotFound",
    "TrufflehogError",
    "check",
    "lib",
    "native_library_path",
    "take",
]


class TrufflehogError(RuntimeError):
    """Raised when the native scanner reports a failure."""


class NativeLibraryNotFound(TrufflehogError, FileNotFoundError):
    """Raised when the compiled shared library cannot be located."""


#: Environment variable to point at a library built somewhere else. Useful for
#: development and for distro packagers who build the .so out of tree.
LIB_PATH_ENV: Final = "LITELLM_TRUFFLEHOG_LIB"

_STEM: Final = "libthscan"


def _library_filename() -> str:
    if sys.platform == "win32":
        return f"{_STEM}.dll"
    if sys.platform == "darwin":
        return f"{_STEM}.dylib"
    return f"{_STEM}.so"


def native_library_path() -> Path:
    """Locate the shared library, honouring the override environment variable."""
    override = os.environ.get(LIB_PATH_ENV)
    if override:
        path = Path(override)
        if not path.is_file():
            raise NativeLibraryNotFound(f"{LIB_PATH_ENV} points at {path}, which does not exist")
        return path

    candidate = Path(__file__).parent / "_native" / _library_filename()
    if candidate.is_file():
        return candidate

    raise NativeLibraryNotFound(
        f"Could not find {_library_filename()} in {candidate.parent}.\n"
        "The Go library has not been built for this platform. Build it with:\n"
        "    make dev\n"
        f"or set {LIB_PATH_ENV} to an existing build."
    )


def _load() -> ctypes.CDLL:
    path = native_library_path()
    try:
        dll = ctypes.CDLL(str(path))
    except OSError as exc:  # pragma: no cover - platform/toolchain specific
        raise NativeLibraryNotFound(f"Failed to load {path}: {exc}") from exc

    # Returned strings are declared as void* so the pointer survives for th_free.
    dll.th_version.argtypes = []
    dll.th_version.restype = ctypes.c_void_p

    dll.th_profiles.argtypes = []
    dll.th_profiles.restype = ctypes.c_void_p

    dll.th_last_error.argtypes = []
    dll.th_last_error.restype = ctypes.c_void_p

    dll.th_free.argtypes = [ctypes.c_void_p]
    dll.th_free.restype = None

    dll.th_new.argtypes = [ctypes.c_char_p]
    dll.th_new.restype = ctypes.c_longlong

    dll.th_close.argtypes = [ctypes.c_longlong]
    dll.th_close.restype = ctypes.c_int

    dll.th_detector_count.argtypes = [ctypes.c_longlong]
    dll.th_detector_count.restype = ctypes.c_longlong

    dll.th_warmup_errors.argtypes = [ctypes.c_longlong]
    dll.th_warmup_errors.restype = ctypes.c_void_p

    dll.th_scan.argtypes = [ctypes.c_longlong, ctypes.c_char_p, ctypes.c_int]
    dll.th_scan.restype = ctypes.c_void_p

    return dll


class _LazyLib:
    """Defers dlopen until first use.

    Importing this package must stay cheap and must not fail on a machine where
    the library was never built - the LiteLLM proxy imports plugin modules
    eagerly, and an ImportError there is far harder to diagnose than a clear
    error at first scan.
    """

    __slots__ = ("_dll",)

    def __init__(self) -> None:
        self._dll: ctypes.CDLL | None = None

    def __getattr__(self, name: str):
        if self._dll is None:
            self._dll = _load()
        return getattr(self._dll, name)


lib = _LazyLib()


def take(ptr: int | None) -> str | None:
    """Decode a ``char*`` returned by the library and free it.

    Returns ``None`` for a NULL pointer, which the library uses to signal
    failure.
    """
    if not ptr:
        return None
    try:
        return ctypes.string_at(ptr).decode("utf-8", errors="replace")
    finally:
        lib.th_free(ctypes.c_void_p(ptr))


def check(ptr: int | None, action: str) -> str:
    """Like :func:`take`, but raise with the library's error message on NULL."""
    value = take(ptr)
    if value is None:
        raise TrufflehogError(f"{action} failed: {last_error()}")
    return value


def last_error() -> str:
    return take(lib.th_last_error()) or "unknown error"
