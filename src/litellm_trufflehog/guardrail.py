"""LiteLLM guardrail that blocks or redacts secrets in prompts and responses.

See ``examples/config.yaml`` for registration. ``apply_guardrail`` covers all
three modes and both directions, so no per-call-type hook is needed.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal

from .scanner import RedactionError, Scanner, ScanReport, get_scanner
from .stream import DEFAULT_OVERLAP_CHARS, StreamScanner

if TYPE_CHECKING:  # pragma: no cover
    from litellm.integrations.custom_guardrail import CustomGuardrail as _Base
else:
    try:
        from litellm.integrations.custom_guardrail import CustomGuardrail as _Base
    except Exception:  # pragma: no cover - litellm is an optional dependency

        class _Base:  # type: ignore[no-redef]
            """Stand-in keeping this module importable without litellm."""

            def __init__(self, **kwargs: Any) -> None:
                self.optional_params = kwargs


try:  # LiteLLM ships fastapi; fall back cleanly if it is absent.
    from fastapi import HTTPException as _HTTPException
except Exception:  # pragma: no cover
    _HTTPException = None  # type: ignore[assignment]

try:
    from litellm._logging import verbose_proxy_logger as _logger
except Exception:  # pragma: no cover
    _logger = logging.getLogger(__name__)

__all__ = ["OnDetection", "SecretDetected", "TrufflehogGuardrail"]

OnDetection = Literal["block", "redact", "log"]
_VALID_ACTIONS: tuple[str, ...] = ("block", "redact", "log")

#: Characters LiteLLM withholds at the tail of a streamed text so a secret is
#: never split across chunks. Must exceed the longest credential expected.
DEFAULT_STREAM_HOLDBACK_CHARS = 4096


class SecretDetected(Exception):
    """Raised when a call must be blocked.

    The message names only detectors, counts and reasons - never the secret.
    ``reason`` is ``secret_detected``, ``scan_truncated`` or ``scan_error``.
    """

    def __init__(
        self,
        report: ScanReport,
        input_type: str,
        reason: str = "secret_detected",
        message: str | None = None,
    ) -> None:
        self.report = report
        self.input_type = input_type
        self.reason = reason
        if message is None:
            detectors = ", ".join(report.detector_types) or "unknown"
            message = (
                f"Blocked: {len(report.findings)} secret(s) detected in the "
                f"{input_type} by trufflehog ({detectors})."
            )
        super().__init__(message)

    def as_detail(self) -> dict[str, Any]:
        return {
            "error": self.reason,
            "message": str(self),
            "input_type": self.input_type,
            **self.report.summary(),
        }


class TrufflehogGuardrail(_Base):
    """Scans prompt and response text for credentials.

    All parameters are settable from ``litellm_params``:

    on_detection
        ``block`` (default), ``redact`` or ``log``. ``redact`` masks each secret
        with ``[REDACTED:<detector>:<fingerprint>]``, where equal fingerprints mean
        the same credential appeared more than once; see
        :func:`~litellm_trufflehog.fingerprint`.
    profile
        ``minimal``, ``core`` (default), ``all`` or ``paranoid``. ``paranoid`` is
        ``all`` plus ``HighEntropy``, our catch-all detector and the only way to
        catch credentials with no recognisable issuer - at a much higher false
        positive rate, and with matches that can cover the surrounding key name,
        so prefer it with ``block`` or ``log`` over ``redact``.
    detectors / exclude_detectors
        Adjust the profile using trufflehog's selector syntax (``AWS``,
        ``Github.v2``, ``1-10``), plus ``HighEntropy`` for our catch-all and
        ``Generic`` for trufflehog's.
    verify
        Live-verify candidates. **Off by default**: it transmits the candidate
        secret to a third party.
    block_on_truncation / block_on_scan_error
        Default ``True``: an unscanned tail or a skipped detector means an empty
        result cannot be mistaken for a clean one.
    stream_holdback_chars
        Tail LiteLLM withholds so a secret cannot be split across chunks.
    """

    def __init__(
        self,
        *,
        on_detection: OnDetection = "block",
        profile: str | None = None,
        detectors: Sequence[str] | None = None,
        exclude_detectors: Sequence[str] | None = None,
        verify: bool = False,
        filter_entropy: float = 0.0,
        filter_unverified: bool = False,
        drop_wordlist_fps: bool | None = None,
        scan_entire_chunk: bool = False,
        detector_timeout_ms: int = 0,
        concurrency: int = 0,
        max_bytes: int = 0,
        block_on_truncation: bool = True,
        block_on_scan_error: bool = True,
        stream_holdback_chars: int = DEFAULT_STREAM_HOLDBACK_CHARS,
        stream_overlap_chars: int = DEFAULT_OVERLAP_CHARS,
        scanner: Scanner | None = None,
        **kwargs: Any,
    ) -> None:
        action = str(on_detection).lower()
        if action not in _VALID_ACTIONS:
            raise ValueError(f"on_detection must be one of {_VALID_ACTIONS}, got {on_detection!r}")
        self.on_detection: str = action
        self.block_on_truncation = bool(block_on_truncation)
        self.block_on_scan_error = bool(block_on_scan_error)
        self.stream_holdback_chars = int(stream_holdback_chars)
        self.stream_overlap_chars = int(stream_overlap_chars)

        # Eager: resolving detectors and building the prefilter belongs at
        # startup, not inside the first request.
        self._scanner = scanner or get_scanner(
            profile=profile,
            include_detectors=list(detectors) if detectors else None,
            exclude_detectors=list(exclude_detectors) if exclude_detectors else None,
            verify=verify,
            filter_entropy=filter_entropy,
            filter_unverified=filter_unverified,
            drop_wordlist_fps=drop_wordlist_fps,
            scan_entire_chunk=scan_entire_chunk,
            detector_timeout_ms=detector_timeout_ms,
            concurrency=concurrency,
            max_bytes=max_bytes,
        )

        super().__init__(**kwargs)

        _logger.info(
            "litellm-trufflehog ready: on_detection=%s detectors=%d",
            self.on_detection,
            self._scanner.detector_count,
        )

    @property
    def scanner(self) -> Scanner:
        return self._scanner

    # -- main entry point -------------------------------------------------

    async def apply_guardrail(
        self,
        inputs: Any,
        request_data: dict | None = None,
        input_type: Literal["request", "response"] = "request",
        logging_obj: Any = None,
    ) -> Any:
        texts: list[str] = list(inputs.get("texts") or [])

        if texts:
            reports = await asyncio.gather(*(self._scanner.scan_async(text) for text in texts))
            combined = _combine(reports)

            needs_action = (
                bool(combined.findings)
                or (self.block_on_truncation and combined.truncated)
                or (self.block_on_scan_error and combined.degraded)
            )
            if needs_action:
                inputs["texts"] = self._handle(texts, reports, combined, input_type)
            elif combined.degraded:
                _logger.warning(
                    "litellm-trufflehog: scan of %s was degraded but allowed by "
                    "policy (block_on_scan_error=False): %s",
                    input_type,
                    combined.errors,
                )

        # Withhold a tail on streamed text so a secret cannot be split across
        # two chunks and slip past scanning.
        if self.stream_holdback_chars > 0:
            inputs["stream_holdback_chars"] = self.stream_holdback_chars

        return inputs

    def _handle(
        self,
        texts: list[str],
        reports: Sequence[ScanReport],
        combined: ScanReport,
        input_type: str,
    ) -> list[str]:
        """Apply the configured action. Returns the (possibly masked) texts."""
        # Untrustworthy scans are rejected before the on_detection policy: "log"
        # and "redact" both imply we know what is in the text.
        if self.block_on_scan_error and combined.degraded:
            _logger.warning(
                "litellm-trufflehog: detector failures while scanning %s, blocking "
                "because an empty result cannot be trusted: %s",
                input_type,
                combined.errors,
            )
            raise self._blocked(
                combined,
                input_type,
                reason="scan_error",
                message=(
                    "Blocked: the secret scan did not complete "
                    f"({len(combined.errors)} detector failure(s)), so the "
                    f"{input_type} could not be cleared."
                ),
            )

        if self.block_on_truncation and combined.truncated:
            _logger.warning(
                "litellm-trufflehog: %s exceeded max_bytes; blocking because the "
                "unscanned tail cannot be cleared",
                input_type,
            )
            raise self._blocked(
                combined,
                input_type,
                reason="scan_truncated",
                message=(
                    f"Blocked: the {input_type} exceeded the scan size limit, so "
                    "its tail could not be cleared."
                ),
            )

        if self.on_detection == "log":
            _logger.warning(
                "litellm-trufflehog: secrets detected in %s (allowed by policy): %s",
                input_type,
                combined.summary(),
            )
            return texts

        if self.on_detection == "redact":
            try:
                # strict=True: a length mismatch would silently drop the tail of
                # `texts`, leaving it unredacted.
                masked = [
                    self._scanner._apply_redaction(text, report) if report.findings else text
                    for text, report in zip(texts, reports, strict=True)
                ]
            except RedactionError as exc:
                # Fail closed: a secret we cannot locate cannot be masked.
                _logger.warning(
                    "litellm-trufflehog: redaction impossible (%s); blocking instead", exc
                )
                raise self._blocked(combined, input_type) from exc

            _logger.warning(
                "litellm-trufflehog: redacted secrets in %s: %s",
                input_type,
                combined.summary(),
            )
            return masked

        raise self._blocked(combined, input_type)

    def _blocked(
        self,
        report: ScanReport,
        input_type: str,
        reason: str = "secret_detected",
        message: str | None = None,
    ) -> Exception:
        error = SecretDetected(report, input_type, reason=reason, message=message)
        if _HTTPException is not None:
            return _HTTPException(status_code=400, detail=error.as_detail())
        return error

    # -- streaming --------------------------------------------------------

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[Any, None]:
        """Scan a streaming response chunk by chunk, over an overlapping window.

        On detection the stream is terminated by raising, which stops *further*
        content only: chunks already yielded have been delivered.
        """
        stream = StreamScanner(self._scanner, overlap_chars=self.stream_overlap_chars)

        async for item in response:
            text = _extract_stream_text(item)
            if text:
                report = stream.feed(text)
                if report.findings:
                    if self.on_detection == "log":
                        _logger.warning(
                            "litellm-trufflehog: secrets in streamed response "
                            "(allowed by policy): %s",
                            report.summary(),
                        )
                    else:
                        # "redact" is unsafe mid-stream: a partial secret may
                        # already have been emitted.
                        _logger.warning(
                            "litellm-trufflehog: terminating stream, secrets detected: %s",
                            report.summary(),
                        )
                        raise self._blocked(report, "response")
            yield item


def _combine(reports: Sequence[ScanReport]) -> ScanReport:
    """Merge per-text reports into one."""
    if len(reports) == 1:
        return reports[0]
    return ScanReport(
        findings=tuple(f for r in reports for f in r.findings),
        scanned_bytes=sum(r.scanned_bytes for r in reports),
        duration_ms=sum(r.duration_ms for r in reports),
        truncated=any(r.truncated for r in reports),
        errors=tuple(e for r in reports for e in r.errors),
    )


def _extract_stream_text(item: Any) -> str:
    """Pull assistant text out of a streaming chunk.

    LiteLLM yields ``ModelResponseStream`` objects; tests and other providers may
    yield dicts. Both are handled without importing litellm types.
    """
    if isinstance(item, str):
        return item

    choices = _get(item, "choices") or ()
    parts: list[str] = []
    for choice in choices:
        delta = _get(choice, "delta")
        if delta is None:
            continue
        content = _get(delta, "content")
        if isinstance(content, str) and content:
            parts.append(content)
    return "".join(parts)


def _get(obj: Any, key: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)
