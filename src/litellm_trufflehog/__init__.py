"""Fast trufflehog secret scanning for LiteLLM.

Wraps trufflehog's detector engine as a Go shared library and exposes it to
Python, plus a LiteLLM guardrail that blocks or redacts secrets in prompts and
responses.

Quick start::

    from litellm_trufflehog import Scanner

    with Scanner() as scanner:
        report = scanner.scan("my key is ghp_...")
        if report:
            print(report.summary())

Verification is off by default. Enabling it transmits candidate secrets to
third-party APIs to test whether they are live; do not enable it casually.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._lib import LIB_PATH_ENV, NativeLibraryNotFound, TrufflehogError, native_library_path
from .scanner import (
    REDACTION_TEMPLATE,
    Finding,
    RedactionError,
    ScanReport,
    Scanner,
    Span,
    get_scanner,
    native_version,
    profiles,
)
from .stream import DEFAULT_OVERLAP_CHARS, StreamScanner

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # scanning
    "Scanner",
    "ScanReport",
    "Finding",
    "Span",
    "get_scanner",
    "StreamScanner",
    "DEFAULT_OVERLAP_CHARS",
    # redaction
    "REDACTION_TEMPLATE",
    "RedactionError",
    # errors / introspection
    "TrufflehogError",
    "NativeLibraryNotFound",
    "LIB_PATH_ENV",
    "native_library_path",
    "native_version",
    "profiles",
    # guardrail (lazily imported: litellm is an optional dependency)
    "TrufflehogGuardrail",
    "OnDetection",
]

if TYPE_CHECKING:
    from .guardrail import OnDetection, TrufflehogGuardrail


def __getattr__(name: str) -> Any:
    """Import the guardrail on demand.

    ``litellm`` is an optional dependency: the scanner is useful standalone, and
    importing litellm eagerly would make this package unusable without it.
    """
    if name in ("TrufflehogGuardrail", "OnDetection"):
        from . import guardrail

        return getattr(guardrail, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
