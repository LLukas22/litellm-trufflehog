"""Tests for the ctypes loader itself, independent of scanning."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from litellm_trufflehog import _lib


def test_lazy_lib_ignores_attribute_probes() -> None:
    """A non-export attribute must raise without loading the library.

    pytest asks every module-level object for ``__test__`` during collection, and
    inspect, copy and pickle probe their own dunders. If those probes triggered
    the load, importing the module anywhere would dlopen ~70 MB at an arbitrary
    moment - and on a machine without the library built, an unrelated tool's
    introspection would raise NativeLibraryNotFound.
    """
    fresh = _lib._LazyLib()

    for name in ("__test__", "__wrapped__", "__all__", "__deepcopy__", "not_an_export"):
        with pytest.raises(AttributeError):
            getattr(fresh, name)
        assert fresh._dll is None, f"{name!r} probe should not have loaded the library"


def test_lazy_lib_loads_real_exports(native_available: bool) -> None:
    fresh = _lib._LazyLib()
    assert fresh._dll is None
    assert callable(fresh.th_version)
    assert fresh._dll is not None


def test_stdio_is_usable_under_normal_conditions() -> None:
    # pytest redirects these to temp files, which are still perfectly usable.
    assert _lib._stdio_is_usable(1)
    assert _lib._stdio_is_usable(2)


def test_repair_is_a_noop_when_handles_work() -> None:
    """Working streams must be left alone, or host output would go to the void."""
    assert _lib._repair_standard_handles() == []


@pytest.mark.slow
def test_loads_with_closed_standard_handles(tmp_path: Path, native_available: bool) -> None:
    """Loading must survive a host that closed stdout and stderr.

    A daemonised proxy (systemd without a journal, a Windows service, ``nohup``
    with fds closed) has no usable standard handles. The Go runtime binds them
    when the library loads, and a dependency then hands os.Stdout to wazero
    unchecked; the resulting panic aborts the *host* process, so this has to work
    rather than merely fail cleanly.
    """
    marker = tmp_path / "result.txt"
    # .../src/litellm_trufflehog/_lib.py -> .../src
    src_root = str(Path(_lib.__file__).resolve().parents[1])

    script = textwrap.dedent(f"""
        import os
        os.close(1)
        os.close(2)

        import litellm_trufflehog as t

        scanner = t.Scanner(profile="minimal")
        report = scanner.scan("token ghp_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5")
        with open({str(marker)!r}, "w", encoding="utf-8") as fh:
            fh.write(f"{{scanner.detector_count}},{{len(report.findings)}}")
    """)

    env = dict(os.environ)
    env["PYTHONPATH"] = src_root + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )

    assert proc.returncode == 0, (
        f"loading with closed handles aborted (exit {proc.returncode}); "
        f"stderr={proc.stderr[-2000:]!r}"
    )
    detectors, findings = marker.read_text(encoding="utf-8").split(",")
    assert int(detectors) > 0
    assert int(findings) == 1, "the scan must still work, not just avoid crashing"
