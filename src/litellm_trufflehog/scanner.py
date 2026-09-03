"""High-level scanning API."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import secrets
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ._lib import TrufflehogError, check, last_error, lib

__all__ = [
    "FINGERPRINT_BYTES",
    "REDACTION_TEMPLATE",
    "Finding",
    "RedactionError",
    "ScanReport",
    "Scanner",
    "Span",
    "fingerprint",
    "get_scanner",
    "native_version",
    "profiles",
]

#: Replacement written over a detected secret. ``{detector}`` and
#: ``{fingerprint}`` are substituted; a template may use either or neither.
REDACTION_TEMPLATE = "[REDACTED:{detector}:{fingerprint}]"

#: Digest length of a fingerprint in bytes; renders as twice as many hex characters.
FINGERPRINT_BYTES = 4

#: Keyed, so that a fingerprint cannot be attacked back to its secret: unlike a
#: finding's SHA-256, this tag leaves the trust boundary inside the redacted text,
#: and a short *unkeyed* digest of a weak password would be trivial to crack.
#:
#: The key is random per process, which makes tags comparable for the lifetime of
#: one worker and meaningless anywhere else.
_FINGERPRINT_KEY = secrets.token_bytes(32)


def fingerprint(secret: str | bytes) -> str:
    """Return a short, non-reversible tag identifying a secret value.

    Equal secrets produce equal fingerprints within a process, so the redacted
    text shows whether two masked spans held the same credential. Deliberately
    *not* stable across processes or restarts: see :data:`_FINGERPRINT_KEY`.
    """
    data = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    return hashlib.blake2b(data, key=_FINGERPRINT_KEY, digest_size=FINGERPRINT_BYTES).hexdigest()


class RedactionError(TrufflehogError):
    """Redaction cannot guarantee the secret was removed. Treat as a block."""


@dataclass(frozen=True, slots=True)
class Span:
    """A byte range in the UTF-8 encoding of the scanned text."""

    start: int
    end: int

    def __len__(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected secret."""

    detector_type: str
    secret_sha256: str
    spans: tuple[Span, ...] = ()
    detector_name: str = ""
    description: str = ""
    verified: bool = False
    verification_error: str = ""
    redacted: str = ""
    raw: str = ""
    extra_data: Mapping[str, str] = field(default_factory=dict)
    wordlist_false_positive: bool = False

    @property
    def redactable(self) -> bool:
        """Whether every part of this credential was located in the input.

        False when a detector normalised or recombined its match; such a finding
        can only be blocked.
        """
        return bool(self.spans)

    @property
    def label(self) -> str:
        """Human-readable detector label, safe to log."""
        return self.detector_name or self.detector_type

    @classmethod
    def _from_json(cls, obj: Mapping[str, Any]) -> Finding:
        return cls(
            detector_type=obj.get("detector_type", "unknown"),
            secret_sha256=obj.get("secret_sha256", ""),
            spans=tuple(Span(int(s["start"]), int(s["end"])) for s in obj.get("spans") or ()),
            detector_name=obj.get("detector_name", "") or "",
            description=obj.get("description", "") or "",
            verified=bool(obj.get("verified", False)),
            verification_error=obj.get("verification_error", "") or "",
            redacted=obj.get("redacted", "") or "",
            raw=obj.get("raw", "") or "",
            extra_data=dict(obj.get("extra_data") or {}),
            wordlist_false_positive=bool(obj.get("wordlist_false_positive", False)),
        )


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Result of scanning one piece of text."""

    findings: tuple[Finding, ...] = ()
    scanned_bytes: int = 0
    duration_ms: float = 0.0
    truncated: bool = False
    errors: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        """True when anything was detected."""
        return bool(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    @property
    def detector_types(self) -> tuple[str, ...]:
        """Distinct detector labels, sorted. Safe to log or return to a client."""
        return tuple(sorted({f.label for f in self.findings}))

    @property
    def fully_redactable(self) -> bool:
        """Whether masking spans would remove every detected secret."""
        return all(f.redactable for f in self.findings)

    @property
    def degraded(self) -> bool:
        """Whether a detector failed, making "no findings" untrustworthy.

        A skipped detector means an empty report may mean "we did not manage to
        look"; allow/deny decisions must fail closed.
        """
        return bool(self.errors)

    @property
    def trustworthy(self) -> bool:
        """True when the scan covered the whole input with no detector failures."""
        return not self.degraded and not self.truncated

    def summary(self) -> dict[str, Any]:
        """A log/response-safe summary, containing no secret material."""
        return {
            "secrets_detected": len(self.findings),
            "detectors": list(self.detector_types),
            "verified": sum(1 for f in self.findings if f.verified),
            "truncated": self.truncated,
            "degraded": self.degraded,
            "scan_errors": list(self.errors),
            "scanned_bytes": self.scanned_bytes,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def _from_json(cls, obj: Mapping[str, Any]) -> ScanReport:
        return cls(
            findings=tuple(Finding._from_json(f) for f in obj.get("findings") or ()),
            scanned_bytes=int(obj.get("scanned_bytes", 0)),
            duration_ms=float(obj.get("duration_ms", 0.0)),
            truncated=bool(obj.get("truncated", False)),
            errors=tuple(obj.get("errors") or ()),
        )


def _merge_labelled_spans(
    findings: Iterable[Finding],
) -> list[tuple[int, int, str]]:
    """Flatten findings into non-overlapping (start, end, label) triples.

    Two detectors can match the same bytes, so ranges are merged to keep the
    splice monotonic.
    """
    spans: list[tuple[int, int, str]] = [
        (s.start, s.end, f.label) for f in findings for s in f.spans if len(s) > 0
    ]
    if not spans:
        return []
    spans.sort(key=lambda t: (t[0], -t[1]))

    merged: list[tuple[int, int, str]] = [spans[0]]
    for start, end, label in spans[1:]:
        last_start, last_end, last_label = merged[-1]
        if start <= last_end:
            if label != last_label and label not in last_label.split("+"):
                last_label = f"{last_label}+{label}"
            merged[-1] = (last_start, max(last_end, end), last_label)
        else:
            merged.append((start, end, label))
    return merged


class Scanner:
    """A reusable, thread-safe secret scanner backed by trufflehog's detectors.

    Construction resolves the detector set and builds the Aho-Corasick
    prefilter, so create one and reuse it. Keyword arguments map to the Go
    ``scanner.Config`` fields; see the README.
    """

    __slots__ = ("_closed", "_config", "_handle", "_lock")

    def __init__(
        self,
        *,
        profile: str | None = None,
        include_detectors: Sequence[str] | None = None,
        exclude_detectors: Sequence[str] | None = None,
        verify: bool = False,
        filter_entropy: float = 0.0,
        filter_unverified: bool = False,
        drop_wordlist_fps: bool | None = None,
        scan_entire_chunk: bool = False,
        detector_timeout_ms: int = 0,
        concurrency: int = 0,
        include_raw: bool = False,
        max_bytes: int = 0,
    ) -> None:
        config: dict[str, Any] = {}
        if profile is not None:
            config["profile"] = profile
        if include_detectors:
            config["include_detectors"] = list(include_detectors)
        if exclude_detectors:
            config["exclude_detectors"] = list(exclude_detectors)
        if verify:
            config["verify"] = True
        if filter_entropy:
            config["filter_entropy"] = float(filter_entropy)
        if filter_unverified:
            config["filter_unverified"] = True
        if drop_wordlist_fps is not None:
            config["drop_wordlist_fps"] = bool(drop_wordlist_fps)
        if scan_entire_chunk:
            config["scan_entire_chunk"] = True
        if detector_timeout_ms:
            config["detector_timeout_ms"] = int(detector_timeout_ms)
        if concurrency:
            config["concurrency"] = int(concurrency)
        if include_raw:
            config["include_raw"] = True
        if max_bytes:
            config["max_bytes"] = int(max_bytes)

        self._config = config
        self._lock = threading.Lock()
        self._closed = False

        handle = lib.th_new(json.dumps(config).encode("utf-8"))
        if handle < 0:
            raise TrufflehogError(f"failed to create scanner: {last_error()}")
        self._handle = int(handle)

    # -- introspection ----------------------------------------------------

    @property
    def config(self) -> Mapping[str, Any]:
        return dict(self._config)

    @property
    def detector_count(self) -> int:
        """Number of active detectors."""
        self._ensure_open()
        return int(lib.th_detector_count(self._handle))

    @property
    def warmup_errors(self) -> list[str]:
        """Detectors that failed one-time init; non-empty means reduced coverage."""
        self._ensure_open()
        payload = check(lib.th_warmup_errors(self._handle), "warmup_errors")
        return json.loads(payload) or []

    # -- scanning ---------------------------------------------------------

    def scan(self, text: str | bytes) -> ScanReport:
        """Scan text and return the findings."""
        self._ensure_open()
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        if not data:
            return ScanReport()

        payload = check(lib.th_scan(self._handle, data, len(data)), "scan")
        return ScanReport._from_json(json.loads(payload))

    async def scan_async(self, text: str | bytes) -> ScanReport:
        """Scan off the event loop; ctypes drops the GIL during the native call."""
        return await asyncio.to_thread(self.scan, text)

    # -- redaction --------------------------------------------------------

    def redact(self, text: str, *, template: str = REDACTION_TEMPLATE) -> tuple[str, ScanReport]:
        """Mask every detected secret in ``text``, returning it with the report.

        Raises :class:`RedactionError` if a finding could not be located, since
        the returned text would still contain a secret.
        """
        report = self.scan(text)
        if not report.findings:
            return text, report
        return self._apply_redaction(text, report, template=template), report

    async def redact_async(
        self, text: str, *, template: str = REDACTION_TEMPLATE
    ) -> tuple[str, ScanReport]:
        report = await self.scan_async(text)
        if not report.findings:
            return text, report
        return (
            await asyncio.to_thread(self._apply_redaction, text, report, template=template),
            report,
        )

    @staticmethod
    def _apply_redaction(
        text: str, report: ScanReport, *, template: str = REDACTION_TEMPLATE
    ) -> str:
        """Splice replacements over the reported byte spans.

        Go reports UTF-8 byte offsets, so the splice happens on bytes: slicing
        the ``str`` would use code point indices and corrupt non-ASCII text.

        Each replacement carries a :func:`fingerprint` of the bytes it covers, so
        repeated masks can be told apart: two identical tags mean one credential
        appearing twice, two different tags mean two credentials.
        """
        if not report.fully_redactable:
            unlocatable = sorted({f.label for f in report.findings if not f.redactable})
            raise RedactionError(
                "cannot redact secrets that were not locatable in the input "
                f"(detectors: {', '.join(unlocatable)}); block the request instead"
            )

        raw = text.encode("utf-8")
        pieces: list[bytes] = []
        cursor = 0
        for start, end, label in _merge_labelled_spans(report.findings):
            if start < cursor or end > len(raw):
                raise RedactionError(
                    f"span [{start}:{end}] is out of range for a {len(raw)}-byte input"
                )
            pieces.append(raw[cursor:start])
            replacement = template.format(detector=label, fingerprint=fingerprint(raw[start:end]))
            pieces.append(replacement.encode("utf-8"))
            cursor = end
        pieces.append(raw[cursor:])

        try:
            return b"".join(pieces).decode("utf-8")
        except UnicodeDecodeError as exc:
            # A span landed mid-codepoint; refuse rather than emit mojibake or a
            # partially masked secret.
            raise RedactionError(
                f"redaction produced invalid UTF-8 ({exc}); block the request instead"
            ) from exc

    # -- lifecycle --------------------------------------------------------

    def _ensure_open(self) -> None:
        if self._closed:
            raise TrufflehogError("scanner is closed")

    def close(self) -> None:
        """Release the native scanner. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            # Suppressed: close() also runs from __del__ at interpreter
            # shutdown, when the library may already be gone.
            with contextlib.suppress(Exception):  # pragma: no cover
                lib.th_close(self._handle)

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - GC timing
        with contextlib.suppress(Exception):
            self.close()

    def __repr__(self) -> str:
        state = "closed" if self._closed else f"handle={self._handle}"
        profile = self._config.get("profile", "core")
        return f"<Scanner profile={profile!r} {state}>"


# ---------------------------------------------------------------------------
# Process-wide cache
# ---------------------------------------------------------------------------

_cache: dict[tuple[tuple[str, Any], ...], Scanner] = {}
_cache_lock = threading.Lock()


def _freeze(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def get_scanner(**kwargs: Any) -> Scanner:
    """Return a cached :class:`Scanner` for this configuration.

    Construction is the expensive part, so identical configurations share one
    instance.
    """
    key = tuple(sorted((k, _freeze(v)) for k, v in kwargs.items() if v is not None))
    scanner = _cache.get(key)
    if scanner is not None:
        return scanner
    with _cache_lock:
        scanner = _cache.get(key)
        if scanner is None:
            scanner = Scanner(**kwargs)
            _cache[key] = scanner
        return scanner


def native_version() -> dict[str, str]:
    """Versions of the embedded components (scanner, trufflehog, Go)."""
    return json.loads(check(lib.th_version(), "version"))


def profiles() -> list[str]:
    """Detector profile names supported by the native library."""
    return json.loads(check(lib.th_profiles(), "profiles"))
