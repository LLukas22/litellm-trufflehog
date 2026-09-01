"""Build hooks that compile the Go shared library into the wheel.

Two things need customising beyond the declarative metadata in pyproject.toml:

1. ``build_py`` shells out to ``go build -buildmode=c-shared`` so the compiled
   library lands inside the package directory.

2. ``bdist_wheel`` is told the wheel is platform-specific but *not* tied to a
   CPython ABI. The artifact is pure Python plus one shared library loaded via
   ctypes, so a single ``py3-none-<platform>`` wheel serves every CPython 3.x.
   That is the main practical advantage over building a CPython extension, which
   would require one wheel per interpreter version.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.build_py import build_py as _build_py

HERE = Path(__file__).parent.resolve()
GO_DIR = HERE / "go"
PACKAGE_NATIVE_DIR = HERE / "src" / "litellm_trufflehog" / "_native"

#: Set to a non-empty value to use a library that is already in place instead of
#: invoking the Go toolchain. Useful for CI stages that build once and package
#: several times, and for distro packagers.
SKIP_BUILD_ENV = "LITELLM_TRUFFLEHOG_SKIP_GO_BUILD"


def library_name() -> str:
    if sys.platform == "win32":
        return "libthscan.dll"
    if sys.platform == "darwin":
        return "libthscan.dylib"
    return "libthscan.so"


def build_go_library(destination: Path) -> None:
    """Compile go/cbind into destination."""
    destination.parent.mkdir(parents=True, exist_ok=True)

    if os.environ.get(SKIP_BUILD_ENV):
        if not destination.is_file():
            raise SystemExit(f"{SKIP_BUILD_ENV} is set but {destination} does not exist")
        print(f"{SKIP_BUILD_ENV} set; using existing {destination}")
        return

    if shutil.which("go") is None:
        raise SystemExit(
            "The Go toolchain is required to build litellm-trufflehog from source.\n"
            "Install Go 1.25+ (https://go.dev/dl/) and a C compiler for cgo, or "
            f"set {SKIP_BUILD_ENV}=1 and place a prebuilt library at {destination}."
        )

    env = dict(os.environ)
    env["CGO_ENABLED"] = "1"
    # trufflehog requires a newer toolchain than many systems ship; let Go
    # fetch the one declared in go.mod rather than failing.
    env.setdefault("GOTOOLCHAIN", "auto")

    cmd = [
        "go",
        "build",
        "-buildmode=c-shared",
        # Strip symbols and DWARF: the library is ~145 MB unstripped because of
        # trufflehog's dependency tree.
        "-ldflags=-s -w",
        "-trimpath",
        "-o",
        str(destination),
        "./cbind",
    ]
    print("running:", " ".join(cmd), f"(cwd={GO_DIR})")
    subprocess.run(cmd, cwd=GO_DIR, env=env, check=True)

    if not destination.is_file():
        raise SystemExit(f"go build reported success but {destination} is missing")
    size_mb = destination.stat().st_size / (1024 * 1024)
    print(f"built {destination.name} ({size_mb:.1f} MiB)")


class build_py(_build_py):
    """Compile the Go library, then copy it in with the Python sources."""

    def run(self) -> None:
        build_go_library(PACKAGE_NATIVE_DIR / library_name())
        super().run()


class BinaryDistribution(Distribution):
    """Marks the distribution as containing platform-specific binaries.

    There are no ``ext_modules`` (the library is loaded with ctypes, not linked
    against libpython), so setuptools would otherwise classify the build output
    as pure Python and bury the package under ``<name>.data/purelib/`` in the
    wheel. Declaring extension modules here puts it at the wheel root, where
    auditwheel and installers expect it.
    """

    def has_ext_modules(self) -> bool:
        return True


cmdclass: dict[str, type] = {"build_py": build_py}


try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # pragma: no cover - wheel is a build requirement
    _bdist_wheel = None

if _bdist_wheel is not None:

    class bdist_wheel(_bdist_wheel):
        def get_tag(self) -> tuple[str, str, str]:
            _python, _abi, plat = super().get_tag()
            # No CPython ABI dependency: ctypes loads the library at runtime, so
            # one wheel per platform serves every CPython 3.x.
            return "py3", "none", plat

    cmdclass["bdist_wheel"] = bdist_wheel


setup(cmdclass=cmdclass, distclass=BinaryDistribution)
