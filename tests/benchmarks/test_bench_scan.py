"""Latency and throughput of the scanning path, measured from Python.

`just bench` measures the Go scanner in isolation. These benchmarks measure what
a caller actually pays, which additionally includes the ctypes call, the UTF-8
encode of the input, decoding the JSON report and building the dataclasses.
"""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import CLEAN_TEXT
from litellm_trufflehog import Scanner
from litellm_trufflehog._lib import check, lib

from .conftest import PAYLOAD_SIZES, record_bytes

SIZE_LABELS = [label for label, _ in PAYLOAD_SIZES]


@pytest.fixture(scope="session")
def all_scanner(native_available: bool) -> Iterator[Scanner]:
    """Every shipped detector (~858). The pessimistic configuration."""
    s = Scanner(profile="all")
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Latency and throughput by payload size
# ---------------------------------------------------------------------------


@pytest.mark.benchmark(group="scan-clean")
@pytest.mark.parametrize("size", SIZE_LABELS)
def test_scan_clean(benchmark, bench_scanner: Scanner, clean_payloads, size: str) -> None:
    """Prose with nothing credential-shaped in it: the overwhelmingly common case."""
    text = clean_payloads[size]
    report = benchmark(bench_scanner.scan, text)
    assert not report.findings
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="scan-decoy")
@pytest.mark.parametrize("size", ["2kb", "16kb", "128kb"])
def test_scan_decoy(benchmark, bench_scanner: Scanner, decoy_payloads, size: str) -> None:
    """Text full of credential *keywords* but no valid credentials.

    Every keyword defeats the Aho-Corasick prefilter and forces detectors to run
    their regexes, so this is the realistic worst case for a coding assistant
    whose traffic constantly discusses API keys.
    """
    text = decoy_payloads[size]
    report = benchmark(bench_scanner.scan, text)
    assert not report.findings
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="scan-secret")
@pytest.mark.parametrize("size", ["2kb", "16kb", "128kb"])
def test_scan_with_secret(benchmark, bench_scanner: Scanner, secret_payloads, size: str) -> None:
    """A payload that does contain a credential: match, dedupe and report."""
    text = secret_payloads[size]
    report = benchmark(bench_scanner.scan, text)
    assert report.findings
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="scan-short")
def test_scan_short_chat_turn(benchmark, bench_scanner: Scanner) -> None:
    """A one-line prompt, where fixed per-call overhead dominates entirely."""
    report = benchmark(bench_scanner.scan, CLEAN_TEXT)
    assert not report.findings
    record_bytes(benchmark, len(CLEAN_TEXT.encode("utf-8")))


# ---------------------------------------------------------------------------
# Cost of the detector set
# ---------------------------------------------------------------------------


@pytest.mark.benchmark(group="profile-16kb")
def test_profile_minimal(benchmark, minimal_scanner: Scanner, clean_payloads) -> None:
    text = clean_payloads["16kb"]
    benchmark(minimal_scanner.scan, text)
    record_bytes(benchmark, len(text.encode("utf-8")), detectors=minimal_scanner.detector_count)


@pytest.mark.benchmark(group="profile-16kb")
def test_profile_core(benchmark, bench_scanner: Scanner, clean_payloads) -> None:
    text = clean_payloads["16kb"]
    benchmark(bench_scanner.scan, text)
    record_bytes(benchmark, len(text.encode("utf-8")), detectors=bench_scanner.detector_count)


@pytest.mark.benchmark(group="profile-16kb")
def test_profile_all(benchmark, all_scanner: Scanner, clean_payloads) -> None:
    text = clean_payloads["16kb"]
    benchmark(all_scanner.scan, text)
    record_bytes(benchmark, len(text.encode("utf-8")), detectors=all_scanner.detector_count)


# ---------------------------------------------------------------------------
# Where the Python-side time goes
# ---------------------------------------------------------------------------
#
# Three layers over the same input, in one group so pytest-benchmark prints the
# ratios directly. The deltas isolate the wrapper's cost from the scan's:
#   encode_only  -> just the str -> bytes conversion scan() has to do
#   native_only  -> + ctypes call, native scan, string_at/decode, th_free
#   full_scan    -> + json.loads and dataclass construction


@pytest.mark.benchmark(group="overhead-clean-16kb")
def test_overhead_encode_only(benchmark, clean_payloads) -> None:
    text = clean_payloads["16kb"]
    benchmark(text.encode, "utf-8")
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="overhead-clean-16kb")
def test_overhead_native_only(benchmark, bench_scanner: Scanner, clean_payloads) -> None:
    """The native call without JSON decoding, to price the report parsing."""
    data = clean_payloads["16kb"].encode("utf-8")
    handle = bench_scanner._handle
    n = len(data)

    def call() -> str:
        return check(lib.th_scan(handle, data, n), "scan")

    payload = benchmark(call)
    assert payload.startswith("{")
    record_bytes(benchmark, n, report_json_bytes=len(payload))


@pytest.mark.benchmark(group="overhead-clean-16kb")
def test_overhead_full_scan(benchmark, bench_scanner: Scanner, clean_payloads) -> None:
    text = clean_payloads["16kb"]
    benchmark(bench_scanner.scan, text)
    record_bytes(benchmark, len(text.encode("utf-8")))


# The same split on a payload that produces findings, where the JSON report is
# far larger and the dataclass construction is no longer trivial.


@pytest.mark.benchmark(group="overhead-secret-16kb")
def test_overhead_secret_native_only(benchmark, bench_scanner: Scanner, secret_payloads) -> None:
    data = secret_payloads["16kb"].encode("utf-8")
    handle = bench_scanner._handle
    n = len(data)

    def call() -> str:
        return check(lib.th_scan(handle, data, n), "scan")

    payload = benchmark(call)
    record_bytes(benchmark, n, report_json_bytes=len(payload))


@pytest.mark.benchmark(group="overhead-secret-16kb")
def test_overhead_secret_full_scan(benchmark, bench_scanner: Scanner, secret_payloads) -> None:
    text = secret_payloads["16kb"]
    report = benchmark(bench_scanner.scan, text)
    assert report.findings
    record_bytes(benchmark, len(text.encode("utf-8")))


# ---------------------------------------------------------------------------
# Thread scaling
# ---------------------------------------------------------------------------


@pytest.mark.benchmark(group="threads-16kb")
@pytest.mark.parametrize("threads", [1, 2, 4, 8])
def test_scan_thread_scaling(
    benchmark, bench_scanner: Scanner, clean_payloads, threads: int
) -> None:
    """Aggregate throughput of N concurrent scans on one shared Scanner.

    ctypes releases the GIL around the foreign call, so MB/s should rise with
    thread count. If it stays flat, scans are serialising and the proxy gains
    nothing from dispatching them to a thread pool.
    """
    text = clean_payloads["16kb"]
    nbytes = len(text.encode("utf-8"))
    scan = bench_scanner.scan

    with ThreadPoolExecutor(max_workers=threads) as pool:
        # Submit once before timing so worker threads already exist.
        list(pool.map(scan, [text] * threads))

        def run() -> None:
            for report in pool.map(scan, [text] * threads):
                assert not report.findings

        benchmark(run)

    record_bytes(benchmark, nbytes * threads, threads=threads)


# ---------------------------------------------------------------------------
# One-off construction cost
# ---------------------------------------------------------------------------


@pytest.mark.benchmark(group="construction")
@pytest.mark.parametrize("profile", ["minimal", "core", "all"])
def test_scanner_construction(benchmark, native_available: bool, profile: str) -> None:
    """Paid once per worker process at startup, not per request.

    Deliberately excluded from the throughput table: it is not a per-byte cost.
    """
    created: list[Scanner] = []

    def build() -> None:
        created.append(Scanner(profile=profile))

    try:
        benchmark.pedantic(build, rounds=5, iterations=1, warmup_rounds=1)
    finally:
        for scanner in created:
            scanner.close()
