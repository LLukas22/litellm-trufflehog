"""LiteLLM guardrail behaviour.

These tests drive ``apply_guardrail`` with a plain dict, matching the shape
LiteLLM passes, so the suite runs without litellm installed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Literal

import pytest

from conftest import AWS_KEY_ID, AWS_SECRET, CLEAN_TEXT, GITHUB_PAT, assert_no_secrets
from litellm_trufflehog import Scanner, ScanReport
from litellm_trufflehog.guardrail import (
    DEFAULT_STREAM_HOLDBACK_CHARS,
    SecretDetected,
    TrufflehogGuardrail,
)

try:  # The guardrail raises HTTPException when fastapi is importable.
    from fastapi import HTTPException

    BLOCKED: tuple[type[BaseException], ...] = (HTTPException, SecretDetected)
except ImportError:
    BLOCKED = (SecretDetected,)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def guard(scanner: Scanner) -> TrufflehogGuardrail:
    return TrufflehogGuardrail(scanner=scanner, on_detection="block")


def apply(
    guard: TrufflehogGuardrail,
    texts: list[str],
    input_type: Literal["request", "response"] = "request",
):
    return run(guard.apply_guardrail({"texts": texts}, request_data={}, input_type=input_type))


def blocking_error(exc: BaseException) -> dict:
    """Normalise the raised error to its detail payload.

    The guardrail raises fastapi.HTTPException when available and SecretDetected
    otherwise; both carry the same safe summary.
    """
    detail = getattr(exc, "detail", None)
    if detail is not None:
        return detail
    assert isinstance(exc, SecretDetected)
    return exc.as_detail()


# -- block ------------------------------------------------------------------


def test_clean_request_passes_through(guard: TrufflehogGuardrail) -> None:
    result = apply(guard, [CLEAN_TEXT])
    assert result["texts"] == [CLEAN_TEXT]


def test_secret_in_request_is_blocked(guard: TrufflehogGuardrail) -> None:
    with pytest.raises(BLOCKED) as exc_info:
        apply(guard, [f"my key is {GITHUB_PAT}"])

    detail = blocking_error(exc_info.value)
    assert detail["error"] == "secret_detected"
    assert "Github" in detail["detectors"]
    assert detail["secrets_detected"] >= 1


def test_block_message_never_contains_the_secret(guard: TrufflehogGuardrail) -> None:
    """The whole point: an error body that echoed the secret would re-leak it,
    often into client logs."""
    with pytest.raises(BLOCKED) as exc_info:
        apply(guard, [f"aws={AWS_KEY_ID} secret={AWS_SECRET} gh={GITHUB_PAT}"])

    exc = exc_info.value
    payload = json.dumps(blocking_error(exc)) + str(exc)
    assert_no_secrets(payload)


def test_blocks_when_any_of_several_texts_is_dirty(guard: TrufflehogGuardrail) -> None:
    with pytest.raises(BLOCKED):
        apply(guard, [CLEAN_TEXT, "hello", f"token {GITHUB_PAT}"])


def test_response_direction_is_blocked_too(guard: TrufflehogGuardrail) -> None:
    with pytest.raises(BLOCKED) as exc_info:
        apply(guard, [f"here you go: {GITHUB_PAT}"], input_type="response")
    assert blocking_error(exc_info.value)["input_type"] == "response"


# -- redact -----------------------------------------------------------------


def test_redact_masks_and_allows(scanner: Scanner) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, on_detection="redact")
    result = apply(guard, [f"my key is {GITHUB_PAT} thanks", CLEAN_TEXT])

    assert GITHUB_PAT not in result["texts"][0]
    assert "[REDACTED:Github]" in result["texts"][0]
    assert result["texts"][1] == CLEAN_TEXT


def test_redact_handles_multipart_and_multibyte(scanner: Scanner) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, on_detection="redact")
    text = f"关于 🔑 id={AWS_KEY_ID} secret={AWS_SECRET}"
    result = apply(guard, [text])

    masked = result["texts"][0]
    assert_no_secrets(masked)
    assert "关于" in masked and "🔑" in masked


def test_redact_falls_back_to_block_when_unredactable(scanner: Scanner, monkeypatch) -> None:
    """Fail closed: if a secret cannot be located it cannot be masked, so the
    request must be rejected rather than forwarded."""
    from litellm_trufflehog import RedactionError

    guard = TrufflehogGuardrail(scanner=scanner, on_detection="redact")

    def boom(*args, **kwargs):
        raise RedactionError("synthetic: not locatable")

    # Scanner uses __slots__, so patch the class rather than the instance.
    monkeypatch.setattr(Scanner, "_apply_redaction", staticmethod(boom))

    with pytest.raises(BLOCKED) as exc_info:
        apply(guard, [f"token {GITHUB_PAT}"])
    assert blocking_error(exc_info.value)["error"] == "secret_detected"


# -- log --------------------------------------------------------------------


def test_log_mode_allows_request_unchanged(scanner: Scanner) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, on_detection="log")
    text = f"my key is {GITHUB_PAT}"
    result = apply(guard, [text])
    assert result["texts"] == [text]


# -- streaming holdback -----------------------------------------------------


def test_stream_holdback_is_advertised(guard: TrufflehogGuardrail) -> None:
    """LiteLLM withholds this many trailing characters so a secret cannot be
    split across streamed chunks."""
    result = apply(guard, [CLEAN_TEXT])
    assert result["stream_holdback_chars"] == DEFAULT_STREAM_HOLDBACK_CHARS


def test_stream_holdback_configurable(scanner: Scanner) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, stream_holdback_chars=99)
    assert apply(guard, [CLEAN_TEXT])["stream_holdback_chars"] == 99


def test_stream_holdback_can_be_disabled(scanner: Scanner) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, stream_holdback_chars=0)
    assert "stream_holdback_chars" not in apply(guard, [CLEAN_TEXT])


def test_empty_texts_still_sets_holdback(guard: TrufflehogGuardrail) -> None:
    result = apply(guard, [])
    assert result["stream_holdback_chars"] == DEFAULT_STREAM_HOLDBACK_CHARS


# -- truncation -------------------------------------------------------------


def test_oversized_input_is_blocked_by_default(native_available: bool) -> None:
    """An unscanned tail means the verdict is not trustworthy, so fail closed."""
    small = Scanner(profile="minimal", max_bytes=32)
    guard = TrufflehogGuardrail(scanner=small, block_on_truncation=True)
    try:
        with pytest.raises(BLOCKED) as exc_info:
            apply(guard, ["y" * 500])
        assert blocking_error(exc_info.value)["truncated"] is True
    finally:
        small.close()


def test_truncation_can_be_allowed(native_available: bool) -> None:
    small = Scanner(profile="minimal", max_bytes=32)
    guard = TrufflehogGuardrail(scanner=small, block_on_truncation=False)
    try:
        result = apply(guard, ["y" * 500])
        assert result["texts"] == ["y" * 500]
    finally:
        small.close()


# -- degraded scans must fail closed ----------------------------------------
#
# A detector that panics or times out is skipped, so the scan comes back with no
# findings. Treating that as "clean" would let a secret through precisely when
# scanning is broken, so it must block instead.


def _force_report(monkeypatch, report: ScanReport) -> None:
    async def fake_scan_async(self, text):
        return report

    # Scanner uses __slots__, so patch the class.
    monkeypatch.setattr(Scanner, "scan_async", fake_scan_async)


DEGRADED = ScanReport(
    findings=(),
    scanned_bytes=42,
    errors=("Github.v1: detector panicked: GetFileType /dev/stdout",),
)


def test_degraded_scan_is_blocked_even_with_no_findings(scanner: Scanner, monkeypatch) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, on_detection="block")
    _force_report(monkeypatch, DEGRADED)

    with pytest.raises(BLOCKED) as exc_info:
        apply(guard, ["anything at all"])

    detail = blocking_error(exc_info.value)
    assert detail["error"] == "scan_error"
    assert detail["degraded"] is True
    assert detail["secrets_detected"] == 0


def test_degraded_scan_blocks_in_redact_mode_too(scanner: Scanner, monkeypatch) -> None:
    """'redact' implies we know what is in the text; a degraded scan does not."""
    guard = TrufflehogGuardrail(scanner=scanner, on_detection="redact")
    _force_report(monkeypatch, DEGRADED)

    with pytest.raises(BLOCKED) as exc_info:
        apply(guard, ["anything at all"])
    assert blocking_error(exc_info.value)["error"] == "scan_error"


def test_degraded_scan_can_be_allowed_explicitly(scanner: Scanner, monkeypatch) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, block_on_scan_error=False)
    _force_report(monkeypatch, DEGRADED)

    result = apply(guard, ["anything at all"])
    assert result["texts"] == ["anything at all"]


def test_truncation_reason_is_distinct(native_available: bool) -> None:
    """Truncation and detector failure are different problems and should be
    distinguishable by the caller."""
    small = Scanner(profile="minimal", max_bytes=32)
    guard = TrufflehogGuardrail(scanner=small)
    try:
        with pytest.raises(BLOCKED) as exc_info:
            apply(guard, ["y" * 500])
        assert blocking_error(exc_info.value)["error"] == "scan_truncated"
    finally:
        small.close()


# -- configuration ----------------------------------------------------------


def test_invalid_on_detection_rejected(scanner: Scanner) -> None:
    """Config comes from YAML, so an invalid value must be rejected at runtime
    even though the type annotation forbids it."""
    with pytest.raises(ValueError, match="on_detection"):
        TrufflehogGuardrail(scanner=scanner, on_detection="destroy")  # ty: ignore[invalid-argument-type]


@pytest.mark.skipif(
    "litellm" not in str(TrufflehogGuardrail.__mro__),
    reason="litellm not installed; the fallback base class is in use",
)
def test_integrates_with_real_litellm_base_class(scanner: Scanner) -> None:
    """Pin the litellm integration.

    If litellm renames or moves CustomGuardrail, or stops routing through
    CustomLogger, this fails loudly instead of the guardrail silently falling
    back to the stub base class and never being invoked by the proxy.
    """
    from litellm.integrations.custom_guardrail import CustomGuardrail
    from litellm.integrations.custom_logger import CustomLogger

    guard = TrufflehogGuardrail(scanner=scanner, guardrail_name="trufflehog")
    assert isinstance(guard, CustomGuardrail)
    # The proxy only dispatches CustomLogger instances.
    assert isinstance(guard, CustomLogger)


def test_block_raises_http_400_when_fastapi_present(scanner: Scanner) -> None:
    fastapi_exceptions = pytest.importorskip("fastapi.exceptions")

    guard = TrufflehogGuardrail(scanner=scanner, on_detection="block")
    with pytest.raises(fastapi_exceptions.HTTPException) as exc_info:
        apply(guard, [f"key {GITHUB_PAT}"])

    assert exc_info.value.status_code == 400
    detail = exc_info.value.detail
    assert detail["error"] == "secret_detected"
    assert_no_secrets(json.dumps(detail))


def test_guardrail_builds_its_own_scanner(native_available: bool) -> None:
    guard = TrufflehogGuardrail(profile="minimal", on_detection="block")
    assert guard.scanner.detector_count > 0


def test_guardrail_forwards_detector_selection(native_available: bool) -> None:
    guard = TrufflehogGuardrail(profile="minimal", exclude_detectors=["Github"])
    result = apply(guard, [f"token {GITHUB_PAT}"])
    assert result["texts"] == [f"token {GITHUB_PAT}"]


# -- streaming iterator hook ------------------------------------------------


class _Delta:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.delta = _Delta(content)


class _Chunk:
    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


async def _drain(guard: TrufflehogGuardrail, chunks: list) -> list:
    async def gen():
        for c in chunks:
            yield c

    out = []
    async for item in guard.async_post_call_streaming_iterator_hook(None, gen(), {}):
        out.append(item)
    return out


def test_streaming_hook_passes_clean_chunks(guard: TrufflehogGuardrail) -> None:
    chunks = [_Chunk("Hello "), _Chunk("world"), _Chunk("!")]
    assert len(run(_drain(guard, chunks))) == 3


def test_streaming_hook_blocks_on_split_secret(guard: TrufflehogGuardrail) -> None:
    """The secret is split across deltas, so only the overlapping window finds
    it."""
    chunks = [
        _Chunk("your token is gh"),
        _Chunk("p_Ab3Cd5Ef7Gh9Ij1Kl3"),
        _Chunk("Mn5Op7Qr9St1Uv3Wx5"),
        _Chunk(" enjoy"),
    ]
    with pytest.raises(BLOCKED) as exc_info:
        run(_drain(guard, chunks))
    assert blocking_error(exc_info.value)["error"] == "secret_detected"


def test_streaming_hook_accepts_dict_chunks(guard: TrufflehogGuardrail) -> None:
    chunks = [
        {"choices": [{"delta": {"content": "hi "}}]},
        {"choices": [{"delta": {"content": "there"}}]},
    ]
    assert len(run(_drain(guard, chunks))) == 2


def test_streaming_hook_tolerates_empty_deltas(guard: TrufflehogGuardrail) -> None:
    chunks = [{"choices": [{"delta": {}}]}, {}, _Chunk("ok")]
    assert len(run(_drain(guard, chunks))) == 3


def test_streaming_hook_log_mode_does_not_block(scanner: Scanner) -> None:
    guard = TrufflehogGuardrail(scanner=scanner, on_detection="log")
    chunks = [_Chunk(f"token {GITHUB_PAT}"), _Chunk(" done")]
    assert len(run(_drain(guard, chunks))) == 2
