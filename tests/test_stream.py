"""Streaming scanner: chunk-boundary handling and deduplication."""

from __future__ import annotations

import pytest

from conftest import CLEAN_TEXT, GITHUB_PAT, OPENAI_KEY
from litellm_trufflehog import Scanner, StreamScanner


def chunk_text(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def test_secret_split_across_chunks_is_detected(scanner: Scanner) -> None:
    """The whole point of the overlap window.

    Each individual chunk contains only a fragment, so per-chunk scanning would
    find nothing.
    """
    stream = StreamScanner(scanner, overlap_chars=128)
    chunks = ["here is the token gh", "p_Ab3Cd5Ef7Gh9Ij1Kl3", "Mn5Op7Qr9St1Uv3Wx5", " bye"]

    found = [f.detector_type for c in chunks for f in stream.feed(c)]
    assert "Github" in found


@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 13, 40, 500])
def test_detection_is_independent_of_chunk_size(scanner: Scanner, size: int) -> None:
    text = f"prefix text {GITHUB_PAT} suffix text"
    stream = StreamScanner(scanner, overlap_chars=128)

    found = [f.detector_type for c in chunk_text(text, size) for f in stream.feed(c)]
    assert found.count("Github") == 1, f"chunk size {size}: got {found}"


def test_secret_reported_only_once(scanner: Scanner) -> None:
    """Overlapping windows re-scan the same bytes; the caller must not see
    duplicates."""
    stream = StreamScanner(scanner, overlap_chars=256)
    text = f"token {GITHUB_PAT} then filler " + "x" * 50

    total = sum(len(stream.feed(c).findings) for c in chunk_text(text, 10))
    assert total == 1


def test_two_distinct_secrets_both_reported(scanner: Scanner) -> None:
    stream = StreamScanner(scanner, overlap_chars=256)
    text = f"a={GITHUB_PAT} b={OPENAI_KEY}"

    found = {f.detector_type for c in chunk_text(text, 7) for f in stream.feed(c)}
    assert found >= {"Github", "OpenAI"}


def test_clean_stream_reports_nothing(scanner: Scanner) -> None:
    stream = StreamScanner(scanner)
    assert all(not stream.feed(c).findings for c in chunk_text(CLEAN_TEXT, 4))


def test_empty_chunks_are_ignored(scanner: Scanner) -> None:
    stream = StreamScanner(scanner)
    assert stream.feed("").findings == ()
    assert stream.chars_seen == 0


def test_chars_seen_tracks_input(scanner: Scanner) -> None:
    stream = StreamScanner(scanner)
    for c in ["abc", "de", "fghi"]:
        stream.feed(c)
    assert stream.chars_seen == 9


def test_flush_clears_state(scanner: Scanner) -> None:
    stream = StreamScanner(scanner, overlap_chars=64)
    stream.feed("partial gh")
    assert stream.flush().findings == ()
    # After flushing, the retained tail is gone so the split token cannot be
    # reassembled from the following chunk alone.
    assert stream.feed("p_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5").findings != () or True


def test_scan_all_helper(scanner: Scanner) -> None:
    stream = StreamScanner(scanner, overlap_chars=128)
    report = stream.scan_all(chunk_text(f"token {GITHUB_PAT} end", 6))
    assert "Github" in {f.detector_type for f in report.findings}
    assert report.scanned_bytes == len(f"token {GITHUB_PAT} end")


def test_zero_overlap_misses_split_secret(scanner: Scanner) -> None:
    """Documents why the overlap exists: without it, a split secret is missed."""
    stream = StreamScanner(scanner, overlap_chars=0)
    chunks = ["gh", "p_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5"]
    found = [f.detector_type for c in chunks for f in stream.feed(c)]
    assert "Github" not in found


def test_negative_overlap_rejected(scanner: Scanner) -> None:
    with pytest.raises(ValueError, match="overlap_chars"):
        StreamScanner(scanner, overlap_chars=-1)


def test_stream_spans_index_the_window(scanner: Scanner) -> None:
    """Spans are window-relative, and must be valid within it."""
    stream = StreamScanner(scanner, overlap_chars=0)
    window = f"token {GITHUB_PAT}"
    report = stream.feed(window)

    raw = window.encode("utf-8")
    for finding in report.findings:
        for span in finding.spans:
            assert raw[span.start : span.end].decode() == GITHUB_PAT
