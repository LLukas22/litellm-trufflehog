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

import contextlib
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
        "    just dev\n"
        f"or set {LIB_PATH_ENV} to an existing build."
    )


def _stdio_is_usable(fd: int) -> bool:
    """Whether ``fd`` is what the Go runtime will consider a working handle.

    The check has to mirror how Go finds the handle, which differs by platform:
    on POSIX it uses the file descriptor number, but on Windows it uses
    ``GetStdHandle``, which can still return a stale handle after the
    corresponding descriptor is closed.
    """
    if sys.platform != "win32":
        try:
            os.fstat(fd)
        except OSError:
            return False
        return True

    # -11 is STD_OUTPUT_HANDLE, -12 is STD_ERROR_HANDLE.
    std_id = {1: -11, 2: -12}[fd]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetStdHandle.restype = ctypes.c_void_p
    handle = kernel32.GetStdHandle(ctypes.c_uint32(std_id & 0xFFFFFFFF))
    if not handle:
        return False
    ctypes.set_last_error(0)
    file_type = kernel32.GetFileType(ctypes.c_void_p(handle))
    # FILE_TYPE_UNKNOWN with a non-zero error is the failure wazero reports as
    # "GetFileType /dev/stdout: The handle is invalid".
    return not (file_type == 0 and ctypes.get_last_error() != 0)


def _repair_standard_handles() -> list[int]:
    """Point stdout and/or stderr at the null device if they are unusable.

    Must be called before the library is loaded. Loading it runs the Go runtime's
    initialisation, including the package ``init`` of every trufflehog detector;
    some of those compile a regex, and ``go-re2`` builds its wazero module with
    ``WithStdout(os.Stdout)`` without checking that the handle works. If it does
    not, the Go runtime panics - and a panic during ``dlopen`` aborts the whole
    host process, so a proxy started with its standard handles closed would be
    killed outright rather than merely failing the scan.

    The repair is deliberately permanent. ``go-re2`` captures the handle during
    its initialisation and reuses it for every wazero module it creates later, so
    handing it a descriptor and then closing it again just moves the crash from
    load time to first scan. One descriptor per broken stream, for the life of the
    process, is the price of loading this dependency tree safely.

    Only broken streams are touched, so a host with working output keeps it and
    never loses a line to the null device.

    ``os.dup2`` suffices on both platform families. On Windows the C runtime
    updates the process's standard handles when descriptors 0-2 are duplicated, so
    ``GetStdHandle`` - which is where Go looks - starts returning the new handle
    without an explicit ``SetStdHandle``.

    Returns the descriptors that were replaced, for tests and diagnostics.
    """
    replaced: list[int] = []
    devnull = -1
    for fd in (1, 2):
        if _stdio_is_usable(fd):
            continue
        if devnull < 0:
            devnull = os.open(os.devnull, os.O_RDWR)
        if devnull != fd:
            os.dup2(devnull, fd)
        replaced.append(fd)

    # fds 1 and 2 now hold their own descriptors for the null device, so the
    # working copy is redundant unless it landed on one of them.
    if devnull >= 0 and devnull not in replaced:
        with contextlib.suppress(OSError):
            os.close(devnull)
    return replaced


def _load() -> ctypes.CDLL:
    path = native_library_path()
    _repair_standard_handles()
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

    #: Prefix shared by every symbol the library exports.
    _EXPORT_PREFIX = "th_"

    def __init__(self) -> None:
        self._dll: ctypes.CDLL | None = None

    def __getattr__(self, name: str):
        # Only genuine exports may trigger the load. Without this guard any
        # incidental attribute probe dlopens ~70 MB at an arbitrary moment,
        # which defeats the laziness this class exists for: pytest asks every
        # module-level object for `__test__` during collection, and inspect,
        # copy and pickle probe their own dunders. Worse than the cost is the
        # timing - the load then happens wherever the probe happens, and the
        # Go runtime binds the process's standard handles at that instant.
        if not name.startswith(self._EXPORT_PREFIX):
            raise AttributeError(name)
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
