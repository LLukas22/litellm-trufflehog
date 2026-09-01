"""Scanner behaviour, configuration and lifecycle."""

from __future__ import annotations

import asyncio
import json

import pytest

from conftest import (
    AWS_KEY_ID,
    AWS_SECRET,
    CLEAN_TEXT,
    GITHUB_PAT,
    OPENAI_KEY,
    SLACK_TOKEN,
)
from litellm_trufflehog import (
    Finding,
    ScanReport,
    Scanner,
    Span,
    TrufflehogError,
    get_scanner,
    native_version,
    profiles,
)


def labels(report: ScanReport) -> set[str]:
    return {f.detector_type for f in report.findings}


# -- detection --------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        (f"aws_access_key_id={AWS_KEY_ID}\naws_secret_access_key={AWS_SECRET}", "AWS"),
        (f"my openai key is {OPENAI_KEY}", "OpenAI"),
        (f"git clone with {GITHUB_PAT}", "Github"),
        (f"slack token {SLACK_TOKEN}", "Slack"),
    ],
)
def test_detects_known_secret_shapes(scanner: Scanner, text: str, expected: str) -> None:
    report = scanner.scan(text)
    assert expected in labels(report), f"expected {expected}, got {labels(report)}"
    assert bool(report) is True
    assert len(report) >= 1


@pytest.mark.parametrize(
    "text",
    [
        "",
        CLEAN_TEXT,
        "Write a haiku about databases.",
        "I use AWS, GitHub and OpenAI daily but will not paste any keys here.",
        "aws_access_key_id = REDACTED\naws_secret_access_key = REDACTED",
        "ghp_short",
    ],
)
def test_clean_text_produces_no_findings(scanner: Scanner, text: str) -> None:
    report = scanner.scan(text)
    assert report.findings == ()
    assert bool(report) is False


def test_empty_scan_is_cheap_and_empty(scanner: Scanner) -> None:
    report = scanner.scan("")
    assert report == ScanReport()


# -- spans ------------------------------------------------------------------


def test_spans_are_utf8_byte_offsets(scanner: Scanner) -> None:
    """Offsets index the UTF-8 encoding, not code points.

    With a multibyte prefix, code-point indexing would extract the wrong slice.
    """
    text = f"关于我的密钥 🔑 {GITHUB_PAT} 结束"
    raw = text.encode("utf-8")

    report = scanner.scan(text)
    spans = [s for f in report.findings if f.detector_type == "Github" for s in f.spans]
    assert spans, "expected at least one span"
    for span in spans:
        assert raw[span.start : span.end].decode("utf-8") == GITHUB_PAT


def test_multipart_credential_reports_every_part(scanner: Scanner) -> None:
    """AWS reports Raw=key-id and RawV2="key-id:secret".

    Masking only one span would leave the secret access key in the text, so both
    parts must be located.
    """
    text = f"id={AWS_KEY_ID} secret={AWS_SECRET}"
    raw = text.encode("utf-8")

    aws = [f for f in scanner.scan(text).findings if f.detector_type == "AWS"]
    assert aws, "expected an AWS finding"

    covered = {raw[s.start : s.end].decode() for f in aws for s in f.spans}
    assert AWS_KEY_ID in covered
    assert AWS_SECRET in covered


def test_repeated_secret_gets_one_span_each(scanner: Scanner) -> None:
    text = f"first {GITHUB_PAT} then {GITHUB_PAT}"
    starts = [
        s.start
        for f in scanner.scan(text).findings
        if f.detector_type == "Github"
        for s in f.spans
    ]
    assert len(starts) >= 2
    assert len(set(starts)) == len(starts), "spans must be distinct"


def test_span_length(scanner: Scanner) -> None:
    span = Span(4, 10)
    assert len(span) == 6


# -- secret hygiene ---------------------------------------------------------


def test_raw_secret_is_withheld_by_default(scanner: Scanner) -> None:
    for finding in scanner.scan(f"token {GITHUB_PAT}").findings:
        assert finding.raw == "", "raw secret must not be returned by default"
        assert finding.secret_sha256, "hash should identify the secret instead"


def test_include_raw_is_opt_in(native_available: bool) -> None:
    with Scanner(profile="minimal", include_raw=True) as scanner:
        raws = [f.raw for f in scanner.scan(f"token {GITHUB_PAT}").findings]
    assert any(GITHUB_PAT in r for r in raws)


def test_summary_contains_no_secret_material(scanner: Scanner) -> None:
    text = f"id={AWS_KEY_ID} secret={AWS_SECRET} gh={GITHUB_PAT}"
    summary = json.dumps(scanner.scan(text).summary())
    for secret in (AWS_KEY_ID, AWS_SECRET, GITHUB_PAT):
        assert secret not in summary


def test_report_helpers(scanner: Scanner) -> None:
    report = scanner.scan(f"gh={GITHUB_PAT} openai={OPENAI_KEY}")
    assert report.detector_types == tuple(sorted(report.detector_types))
    assert set(report.detector_types) >= {"Github", "OpenAI"}
    assert report.fully_redactable is True
    assert list(iter(report)) == list(report.findings)
    assert report.summary()["secrets_detected"] == len(report.findings)


# -- configuration ----------------------------------------------------------


def test_profiles_are_ordered_by_size(native_available: bool) -> None:
    counts = {}
    for name in ("minimal", "core", "all"):
        with Scanner(profile=name) as s:
            counts[name] = s.detector_count
    assert counts["minimal"] < counts["core"] < counts["all"]


def test_profiles_listing(native_available: bool) -> None:
    assert set(profiles()) == {"minimal", "core", "all"}


def test_unknown_profile_is_rejected(native_available: bool) -> None:
    with pytest.raises(TrufflehogError, match="unknown profile"):
        Scanner(profile="does-not-exist")


def test_exclude_detectors(native_available: bool) -> None:
    with Scanner(profile="minimal", exclude_detectors=["Github"]) as s:
        assert "Github" not in labels(s.scan(f"token {GITHUB_PAT}"))


def test_include_detectors_widens_profile(native_available: bool) -> None:
    with Scanner(profile="minimal") as base, Scanner(
        profile="minimal", include_detectors=["Vercel", "Notion"]
    ) as wider:
        assert wider.detector_count > base.detector_count


def test_max_bytes_truncates_and_reports(native_available: bool) -> None:
    with Scanner(profile="minimal", max_bytes=16) as s:
        report = s.scan("x" * 64 + GITHUB_PAT)
    assert report.truncated is True
    assert report.scanned_bytes == 16
    assert report.findings == (), "content past max_bytes is not scanned"


def test_verification_is_off_by_default(scanner: Scanner) -> None:
    """No finding may be marked verified: verification requires network calls
    that must never happen implicitly."""
    report = scanner.scan(f"gh={GITHUB_PAT} aws={AWS_KEY_ID} {AWS_SECRET}")
    assert all(f.verified is False for f in report.findings)


def test_wordlist_filter_is_configurable(native_available: bool) -> None:
    placeholder = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"  # contains "abcde"
    text = f"github token {placeholder}"

    with Scanner(profile="minimal") as default:
        assert "Github" not in labels(default.scan(text))

    with Scanner(profile="minimal", drop_wordlist_fps=False) as permissive:
        report = permissive.scan(text)
    assert "Github" in labels(report)
    assert any(f.wordlist_false_positive for f in report.findings)


# -- lifecycle --------------------------------------------------------------


def test_scan_after_close_raises(native_available: bool) -> None:
    s = Scanner(profile="minimal")
    s.close()
    with pytest.raises(TrufflehogError, match="closed"):
        s.scan("anything")


def test_close_is_idempotent(native_available: bool) -> None:
    s = Scanner(profile="minimal")
    s.close()
    s.close()  # must not raise or double-free


def test_context_manager_closes(native_available: bool) -> None:
    with Scanner(profile="minimal") as s:
        assert s.detector_count > 0
    with pytest.raises(TrufflehogError):
        s.scan("x")


def test_repr_does_not_explode(native_available: bool) -> None:
    with Scanner(profile="minimal") as s:
        assert "Scanner" in repr(s)


def test_get_scanner_caches_by_config(native_available: bool) -> None:
    a = get_scanner(profile="minimal")
    b = get_scanner(profile="minimal")
    c = get_scanner(profile="core")
    assert a is b
    assert a is not c


def test_get_scanner_cache_key_handles_sequences(native_available: bool) -> None:
    a = get_scanner(profile="minimal", include_detectors=["Vercel"])
    b = get_scanner(profile="minimal", include_detectors=["Vercel"])
    assert a is b


def test_warmup_reports_no_errors(scanner: Scanner) -> None:
    """Warm-up forces the RE2/wazero WASM runtime to initialise at construction.

    Regression test: that initialisation used to happen inside the first scan and
    could panic when the host's stdio handles were unusable, silently dropping a
    detector from that scan.
    """
    assert scanner.warmup_errors == []


def test_clean_scan_is_trustworthy(scanner: Scanner) -> None:
    report = scanner.scan(CLEAN_TEXT)
    assert report.degraded is False
    assert report.trustworthy is True


def test_degraded_report_is_not_trustworthy() -> None:
    degraded = ScanReport(errors=("SomeDetector: timed out",))
    assert degraded.degraded is True
    assert degraded.trustworthy is False
    # An empty-but-degraded report must not be mistaken for a clean one.
    assert bool(degraded) is False
    assert degraded.summary()["degraded"] is True


def test_truncated_report_is_not_trustworthy() -> None:
    assert ScanReport(truncated=True).trustworthy is False


def test_native_version_reports_trufflehog(native_available: bool) -> None:
    info = native_version()
    assert info["trufflehog"].startswith("v3.")
    assert "go" in info


# -- async ------------------------------------------------------------------


def test_scan_async_matches_sync(scanner: Scanner) -> None:
    text = f"token {GITHUB_PAT}"
    sync = scanner.scan(text)
    async_report = asyncio.run(scanner.scan_async(text))
    assert labels(sync) == labels(async_report)


def test_concurrent_scans_are_safe(scanner: Scanner) -> None:
    """The scanner must tolerate concurrent use; ctypes drops the GIL during the
    native call so these genuinely overlap."""

    async def main() -> list[ScanReport]:
        texts = [f"token {GITHUB_PAT}", CLEAN_TEXT, f"openai {OPENAI_KEY}"] * 8
        return await asyncio.gather(*(scanner.scan_async(t) for t in texts))

    reports = asyncio.run(main())
    assert len(reports) == 24
    assert sum(1 for r in reports if r.findings) == 16


def test_bytes_input_is_accepted(scanner: Scanner) -> None:
    report = scanner.scan(f"token {GITHUB_PAT}".encode())
    assert "Github" in labels(report)


def test_finding_label_prefers_name(native_available: bool) -> None:
    assert Finding(detector_type="AWS", secret_sha256="x").label == "AWS"
    assert (
        Finding(detector_type="CustomRegex", detector_name="acme", secret_sha256="x").label
        == "acme"
    )
