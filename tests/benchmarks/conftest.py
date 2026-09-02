"""Fixtures for the Python-side benchmarks.

These measure the full call path a request pays (ctypes marshalling, native scan,
JSON decoding, dataclass construction), not just the Go scan.

Payloads are deterministic so runs are comparable, and each is asserted to match
(or not match) at session start: a "clean" payload that accidentally matched
would silently benchmark the much slower finding path.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Iterator
from typing import Any

import pytest

from conftest import GITHUB_PAT
from litellm_trufflehog import Scanner

# Bracketing real traffic: a chat turn, a prompt, a RAG context, a large pasted
# file, and one big enough to show the throughput ceiling.
PAYLOAD_SIZES: tuple[tuple[str, int], ...] = (
    ("256b", 256),
    ("2kb", 2 * 1024),
    ("16kb", 16 * 1024),
    ("128kb", 128 * 1024),
    ("1mb", 1024 * 1024),
)

_VOCABULARY = (
    "the model returns a summary of each paragraph and then explains how the "
    "function computes its result while iterating over every element in that "
    "collection before writing output to disk or sending it upstream to the "
    "service which validates request bodies against a schema and rejects any "
    "payload whose fields do not match what documentation describes for this "
    "particular version of our public interface used by downstream consumers"
)
_WORDS: tuple[str, ...] = tuple(_VOCABULARY.split())

# Terms that trip the Aho-Corasick prefilter without forming a valid credential,
# forcing detectors into their regexes. The realistic hot path for a coding
# assistant: text that talks *about* credentials but contains none.
_DECOY_TERMS = (
    "api_key",
    "aws_secret_access_key",
    "AKIA",
    "ghp_",
    "sk-",
    "xoxb-",
    "Bearer",
    "password",
    "client_secret",
    "PRIVATE KEY",
    "token=",
    "AIza",
)


def _prose(nbytes: int, *, seed: int = 20240607) -> str:
    """Deterministic filler prose of approximately ``nbytes`` ASCII bytes."""
    rng = random.Random(seed)
    out: list[str] = []
    size = 0
    while size < nbytes:
        n = rng.randint(6, 14)
        sentence = " ".join(rng.choice(_WORDS) for _ in range(n)).capitalize() + ". "
        out.append(sentence)
        size += len(sentence)
    return "".join(out)[:nbytes]


def _decoy_prose(nbytes: int, *, seed: int = 991) -> str:
    """Prose peppered with credential-shaped decoys that match no detector."""
    rng = random.Random(seed)
    out: list[str] = []
    size = 0
    while size < nbytes:
        # Roughly every third word is a credential keyword.
        vocabulary = _DECOY_TERMS if rng.random() < 0.30 else _WORDS
        piece = f"{rng.choice(vocabulary)} "
        out.append(piece)
        size += len(piece)
    return "".join(out)[:nbytes]


def _with_secret(nbytes: int) -> str:
    """Filler prose with one real-looking credential about 60% of the way in."""
    body = _prose(nbytes)
    cut = int(len(body) * 0.6)
    return f"{body[:cut]} export GITHUB_TOKEN={GITHUB_PAT} {body[cut:]}"


@pytest.fixture(scope="session")
def bench_scanner(native_available: bool) -> Iterator[Scanner]:
    """The scanner under test: default `core` profile, shared as the guardrail
    shares it (one per worker process, reused across requests)."""
    s = Scanner(profile="core")
    assert s.warmup_errors == [], f"degraded scanner would skew results: {s.warmup_errors}"
    yield s
    s.close()


@pytest.fixture(scope="session")
def clean_payloads(bench_scanner: Scanner) -> dict[str, str]:
    payloads = {label: _prose(n) for label, n in PAYLOAD_SIZES}
    for label, text in payloads.items():
        report = bench_scanner.scan(text)
        assert not report.findings, (
            f"clean payload {label} unexpectedly matched {report.detector_types}; "
            "it would benchmark the finding path instead of the clean path"
        )
    return payloads


@pytest.fixture(scope="session")
def decoy_payloads(bench_scanner: Scanner) -> dict[str, str]:
    payloads = {label: _decoy_prose(n) for label, n in PAYLOAD_SIZES}
    for label, text in payloads.items():
        report = bench_scanner.scan(text)
        assert not report.findings, (
            f"decoy payload {label} matched {report.detector_types}; decoys must "
            "trip the prefilter but not the regexes"
        )
    return payloads


@pytest.fixture(scope="session")
def secret_payloads(bench_scanner: Scanner) -> dict[str, str]:
    payloads = {label: _with_secret(n) for label, n in PAYLOAD_SIZES}
    for label, text in payloads.items():
        report = bench_scanner.scan(text)
        assert report.findings, f"secret payload {label} should match a detector"
    return payloads


@pytest.fixture(scope="session")
def bench_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """A loop reused across async benchmarks, so timings measure the coroutine
    rather than loop setup. Not named ``event_loop``: plugins claim that name."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Throughput reporting
# ---------------------------------------------------------------------------
#
# pytest-benchmark has no notion of payload size, so benchmarks record their byte
# count in `extra_info` and this hook turns it into a MB/s table. MB is 1e6 bytes,
# matching `go test -bench`.


def record_bytes(benchmark: Any, nbytes: int, **extra: object) -> None:
    """Tag a benchmark with the payload size so throughput can be derived."""
    benchmark.extra_info["payload_bytes"] = nbytes
    benchmark.extra_info.update(extra)


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    session = getattr(config, "_benchmarksession", None)
    if session is None:
        return

    rows: list[tuple[str, str, str, str, str]] = []
    for bench in getattr(session, "benchmarks", ()) or ():
        info = getattr(bench, "extra_info", None) or {}
        nbytes = info.get("payload_bytes")
        if not nbytes:
            continue
        stats = getattr(bench, "stats", None)
        if stats is None:
            continue
        mean = stats.mean
        rows.append(
            (
                bench.name,
                _fmt_time(mean),
                _fmt_time(stats.median),
                f"{nbytes / mean / 1e6:,.0f}",
                f"{1.0 / mean:,.0f}",
            )
        )

    if not rows:
        return

    header = ("benchmark", "mean", "median", "MB/s", "calls/s")
    widths = [max(len(str(r[i])) for r in (*rows, header)) for i in range(len(header))]
    write = terminalreporter.write_line

    write("")
    terminalreporter.section("latency and throughput", sep="-")
    write("  ".join(h.ljust(w) for h, w in zip(header, widths, strict=True)))
    write("  ".join("-" * w for w in widths))
    for row in rows:
        write("  ".join(str(c).ljust(w) for c, w in zip(row, widths, strict=True)))
    write("")
    write("MB/s uses MB = 1e6 bytes, as `go test -bench` does. calls/s is per single thread.")


def _fmt_time(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:,.1f} us"
    if seconds < 1.0:
        return f"{seconds * 1e3:,.2f} ms"
    return f"{seconds:,.3f} s"
