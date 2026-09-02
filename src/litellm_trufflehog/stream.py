"""Incremental scanning for streamed responses.

A secret can straddle a chunk boundary (``"ghp_abc"`` then ``"def..."``), so
successive windows overlap, mirroring trufflehog's own 3 KiB peek size.

Prefer LiteLLM's mechanism where you can: returning ``stream_holdback_chars``
from ``apply_guardrail`` makes the proxy withhold a tail so a match is never
split. This module is for the ``async_post_call_streaming_iterator_hook`` path,
where you own the chunk loop.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .scanner import Finding, Scanner, ScanReport, get_scanner

__all__ = ["DEFAULT_OVERLAP_CHARS", "StreamScanner"]

#: Characters of already-scanned text prepended to each window. Any credential
#: shorter than this is seen whole in some window.
DEFAULT_OVERLAP_CHARS = 3072


class StreamScanner:
    """Scans a stream of text fragments, reporting each secret once.

    Not thread-safe: one instance belongs to one stream.
    """

    __slots__ = ("_chars_seen", "_overlap", "_scanner", "_seen", "_tail")

    def __init__(
        self,
        scanner: Scanner | None = None,
        *,
        overlap_chars: int = DEFAULT_OVERLAP_CHARS,
        **scanner_kwargs: Any,
    ) -> None:
        if overlap_chars < 0:
            raise ValueError("overlap_chars must be >= 0")
        self._scanner = scanner if scanner is not None else get_scanner(**scanner_kwargs)
        self._overlap = overlap_chars
        self._tail = ""
        self._seen: set[tuple[str, str]] = set()
        self._chars_seen = 0

    @property
    def scanner(self) -> Scanner:
        return self._scanner

    @property
    def chars_seen(self) -> int:
        return self._chars_seen

    def feed(self, chunk: str) -> ScanReport:
        """Scan a new fragment and return only newly discovered secrets.

        Spans are offsets into the scan *window* (overlap tail + chunk), not
        into the overall stream.
        """
        if not chunk:
            return ScanReport()
        self._chars_seen += len(chunk)

        window = self._tail + chunk
        report = self._scanner.scan(window)

        # Retain the tail for the next window.
        self._tail = window[-self._overlap :] if self._overlap else ""

        return self._only_new(report)

    def flush(self) -> ScanReport:
        """Finish the stream. The tail is already scanned, so this only frees state."""
        self._tail = ""
        return ScanReport()

    def scan_all(self, chunks: Iterable[str]) -> ScanReport:
        """Convenience: feed every chunk and return the union of new findings."""
        findings: list[Finding] = []
        errors: list[str] = []
        truncated = False
        for chunk in chunks:
            report = self.feed(chunk)
            findings.extend(report.findings)
            errors.extend(report.errors)
            truncated = truncated or report.truncated
        return ScanReport(
            findings=tuple(findings),
            scanned_bytes=self._chars_seen,
            truncated=truncated,
            errors=tuple(errors),
        )

    def _only_new(self, report: ScanReport) -> ScanReport:
        """Drop secrets already reported: overlapping windows re-see them."""
        fresh: list[Finding] = []
        for finding in report.findings:
            key = (finding.detector_type, finding.secret_sha256)
            if key in self._seen:
                continue
            self._seen.add(key)
            fresh.append(finding)

        if len(fresh) == len(report.findings):
            return report
        return ScanReport(
            findings=tuple(fresh),
            scanned_bytes=report.scanned_bytes,
            duration_ms=report.duration_ms,
            truncated=report.truncated,
            errors=report.errors,
        )
