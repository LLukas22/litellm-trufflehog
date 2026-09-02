"""Redaction correctness, especially UTF-8 offset handling."""

from __future__ import annotations

import pytest

from conftest import (
    AWS_KEY_ID,
    AWS_SECRET,
    CLEAN_TEXT,
    GITHUB_PAT,
    OPENAI_KEY,
    SLACK_TOKEN,
    assert_no_secrets,
)
from litellm_trufflehog import RedactionError, Scanner, ScanReport, Span
from litellm_trufflehog.scanner import Finding, _merge_labelled_spans


def test_redacts_single_secret(scanner: Scanner) -> None:
    text = f"my token is {GITHUB_PAT} ok"
    masked, report = scanner.redact(text)

    assert GITHUB_PAT not in masked
    assert "[REDACTED:Github]" in masked
    assert masked.startswith("my token is ")
    assert masked.endswith(" ok")
    assert len(report.findings) >= 1


def test_redacts_every_part_of_multipart_credential(scanner: Scanner) -> None:
    """Both the AWS key id and the secret access key must disappear."""
    text = f"aws_access_key_id={AWS_KEY_ID}\naws_secret_access_key={AWS_SECRET}"
    masked, _ = scanner.redact(text)

    assert AWS_KEY_ID not in masked
    assert AWS_SECRET not in masked


def test_redacts_multiple_distinct_secrets(scanner: Scanner) -> None:
    text = (
        f"aws={AWS_KEY_ID} / {AWS_SECRET}\n"
        f"github={GITHUB_PAT}\n"
        f"openai={OPENAI_KEY}\n"
        f"slack={SLACK_TOKEN}\n"
    )
    masked, report = scanner.redact(text)
    assert_no_secrets(masked)
    assert report.fully_redactable


def test_redacts_repeated_occurrences(scanner: Scanner) -> None:
    text = f"a={GITHUB_PAT} b={GITHUB_PAT} c={GITHUB_PAT}"
    masked, _ = scanner.redact(text)
    assert GITHUB_PAT not in masked
    assert masked.count("[REDACTED:Github]") == 3


# -- the UTF-8 trap ---------------------------------------------------------


@pytest.mark.parametrize(
    "prefix,suffix",
    [
        ("关于我的密钥 ", " 结束"),
        ("🔑🔑🔑 ", " 🚀"),
        ("Grüße, hier ist ", " — danke"),
        ("Ключ: ", " конец"),
        ("", ""),
        ("مفتاح ", " نهاية"),
    ],
)
def test_redaction_preserves_non_ascii_context(scanner: Scanner, prefix: str, suffix: str) -> None:
    """Byte offsets must be applied to bytes: slicing the str would shift them."""
    text = f"{prefix}{GITHUB_PAT}{suffix}"
    masked, _ = scanner.redact(text)

    assert GITHUB_PAT not in masked
    assert masked == f"{prefix}[REDACTED:Github]{suffix}"


def test_redaction_with_multibyte_between_two_secrets(scanner: Scanner) -> None:
    text = f"{GITHUB_PAT} 中文字符 emoji 🎉 {OPENAI_KEY}"
    masked, _ = scanner.redact(text)

    assert GITHUB_PAT not in masked
    assert OPENAI_KEY not in masked
    assert "中文字符" in masked
    assert "🎉" in masked


# -- pass-through and failure modes -----------------------------------------


def test_clean_text_is_returned_unchanged(scanner: Scanner) -> None:
    masked, report = scanner.redact(CLEAN_TEXT)
    assert masked == CLEAN_TEXT
    assert report.findings == ()


def test_custom_template(scanner: Scanner) -> None:
    masked, _ = scanner.redact(f"token {GITHUB_PAT}", template="<<{detector} removed>>")
    assert "<<Github removed>>" in masked
    assert GITHUB_PAT not in masked


def test_unlocatable_finding_refuses_to_redact() -> None:
    """A finding without spans cannot be masked, so redaction must fail loudly."""
    report = ScanReport(
        findings=(Finding(detector_type="URI", secret_sha256="deadbeef", spans=()),)
    )
    assert report.fully_redactable is False

    with pytest.raises(RedactionError, match="not locatable"):
        Scanner._apply_redaction("some text", report)


def test_out_of_range_span_is_rejected() -> None:
    report = ScanReport(
        findings=(Finding(detector_type="AWS", secret_sha256="x", spans=(Span(0, 9999),)),)
    )
    with pytest.raises(RedactionError, match="out of range"):
        Scanner._apply_redaction("short", report)


def test_span_landing_mid_codepoint_is_rejected() -> None:
    """Splitting a multibyte character must not yield mojibake."""
    text = "aa€bb"  # € is 3 bytes: e2 82 ac
    report = ScanReport(
        findings=(Finding(detector_type="Test", secret_sha256="x", spans=(Span(0, 3),)),)
    )
    with pytest.raises(RedactionError, match="invalid UTF-8"):
        Scanner._apply_redaction(text, report)


async def _redact_async(scanner: Scanner, text: str):
    return await scanner.redact_async(text)


def test_redact_async(scanner: Scanner) -> None:
    import asyncio

    masked, report = asyncio.run(_redact_async(scanner, f"token {GITHUB_PAT}"))
    assert GITHUB_PAT not in masked
    assert report.findings


# -- span merging -----------------------------------------------------------


def test_merge_labelled_spans_merges_overlaps() -> None:
    findings = (
        Finding(detector_type="A", secret_sha256="1", spans=(Span(0, 10),)),
        Finding(detector_type="B", secret_sha256="2", spans=(Span(5, 15),)),
    )
    merged = _merge_labelled_spans(findings)
    assert merged == [(0, 15, "A+B")]


def test_merge_labelled_spans_keeps_disjoint() -> None:
    findings = (
        Finding(detector_type="A", secret_sha256="1", spans=(Span(0, 4),)),
        Finding(detector_type="B", secret_sha256="2", spans=(Span(10, 14),)),
    )
    assert _merge_labelled_spans(findings) == [(0, 4, "A"), (10, 14, "B")]


def test_merge_labelled_spans_ignores_empty() -> None:
    findings = (Finding(detector_type="A", secret_sha256="1", spans=(Span(3, 3),)),)
    assert _merge_labelled_spans(findings) == []


def test_overlapping_detectors_do_not_corrupt_output(scanner: Scanner) -> None:
    """Two detectors matching overlapping bytes must still produce valid text."""
    text = f"key {OPENAI_KEY} and {GITHUB_PAT}"
    masked, _ = scanner.redact(text)
    assert OPENAI_KEY not in masked
    assert GITHUB_PAT not in masked
    # Output must remain decodable and contain no stray replacement chars.
    assert "\ufffd" not in masked
