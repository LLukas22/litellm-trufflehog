"""End-to-end latency of the guardrail, redaction and streaming paths.

`test_bench_scan.py` measures a single `scan()`. This module measures the whole
per-request path the proxy runs: `apply_guardrail`, which offloads each text to a
worker thread via `asyncio.to_thread` and gathers the results, plus the streaming
hook, whose overlapping-window design makes its cost depend on chunk count rather
than response size.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest

from litellm_trufflehog import Scanner, TrufflehogGuardrail
from litellm_trufflehog.stream import DEFAULT_OVERLAP_CHARS, StreamScanner

from .conftest import record_bytes

#: Characters per streamed delta. A model emits roughly one token per chunk, so
#: a handful of characters; this is what makes chunk counts large.
DELTA_CHARS = 20


def _deltas(text: str, size: int = DELTA_CHARS) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


@pytest.fixture(scope="session")
def guardrail(bench_scanner: Scanner) -> TrufflehogGuardrail:
    return TrufflehogGuardrail(on_detection="block", scanner=bench_scanner)


@pytest.fixture(scope="session")
def redacting_guardrail(bench_scanner: Scanner) -> TrufflehogGuardrail:
    return TrufflehogGuardrail(on_detection="redact", scanner=bench_scanner)


# ---------------------------------------------------------------------------
# apply_guardrail: the per-request cost
# ---------------------------------------------------------------------------


@pytest.mark.benchmark(group="guardrail-clean")
@pytest.mark.parametrize("size", ["256b", "2kb", "16kb"])
def test_guardrail_single_text(
    benchmark, guardrail: TrufflehogGuardrail, clean_payloads, bench_loop, size: str
) -> None:
    """One text per request, the shape of a single-turn completion."""
    text = clean_payloads[size]

    def run() -> Any:
        return bench_loop.run_until_complete(guardrail.apply_guardrail({"texts": [text]}))

    result = benchmark(run)
    assert result["texts"] == [text]
    record_bytes(benchmark, len(text.encode("utf-8")), texts=1)


@pytest.mark.benchmark(group="guardrail-conversation")
@pytest.mark.parametrize("count", [1, 4, 16, 64])
def test_guardrail_many_texts(
    benchmark, guardrail: TrufflehogGuardrail, bench_loop, count: int
) -> None:
    """A multi-turn conversation, where every message is scanned.

    `apply_guardrail` dispatches one `asyncio.to_thread` per text, so this prices
    thread-dispatch overhead against the scan itself. Short messages make that
    overhead visible: it is per-text, not per-byte.
    """
    message = "Please review the deployment script and explain what it does. " * 4
    texts = [message] * count
    nbytes = sum(len(t.encode("utf-8")) for t in texts)

    def run() -> Any:
        return bench_loop.run_until_complete(guardrail.apply_guardrail({"texts": list(texts)}))

    benchmark(run)
    record_bytes(benchmark, nbytes, texts=count)


@pytest.mark.benchmark(group="guardrail-action-16kb")
def test_guardrail_allow(
    benchmark, guardrail: TrufflehogGuardrail, clean_payloads, bench_loop
) -> None:
    text = clean_payloads["16kb"]

    def run() -> Any:
        return bench_loop.run_until_complete(guardrail.apply_guardrail({"texts": [text]}))

    benchmark(run)
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="guardrail-action-16kb")
def test_guardrail_block(
    benchmark, guardrail: TrufflehogGuardrail, secret_payloads, bench_loop
) -> None:
    """The rejection path, including building the sanitised error detail."""
    text = secret_payloads["16kb"]

    def run() -> bool:
        try:
            bench_loop.run_until_complete(guardrail.apply_guardrail({"texts": [text]}))
        except Exception:
            return True
        return False

    assert benchmark(run) is True
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="guardrail-action-16kb")
def test_guardrail_redact(
    benchmark, redacting_guardrail: TrufflehogGuardrail, secret_payloads, bench_loop
) -> None:
    """Masking: scan, then splice replacements over the reported byte spans."""
    text = secret_payloads["16kb"]

    def run() -> Any:
        return bench_loop.run_until_complete(redacting_guardrail.apply_guardrail({"texts": [text]}))

    result = benchmark(run)
    assert "[REDACTED:" in result["texts"][0]
    record_bytes(benchmark, len(text.encode("utf-8")))


# ---------------------------------------------------------------------------
# Redaction in isolation
# ---------------------------------------------------------------------------


@pytest.mark.benchmark(group="redact-16kb")
def test_redact_with_secret(benchmark, bench_scanner: Scanner, secret_payloads) -> None:
    text = secret_payloads["16kb"]
    masked, report = benchmark(bench_scanner.redact, text)
    assert report.findings
    assert "[REDACTED:" in masked
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="redact-16kb")
def test_redact_clean(benchmark, bench_scanner: Scanner, clean_payloads) -> None:
    """No findings, so redact() short-circuits and returns the input unchanged."""
    text = clean_payloads["16kb"]
    masked, report = benchmark(bench_scanner.redact, text)
    assert not report.findings
    assert masked is text
    record_bytes(benchmark, len(text.encode("utf-8")))


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------
#
# StreamScanner rescans an overlap tail with every chunk, so a response streamed
# as N small deltas costs roughly N x (overlap + delta) bytes of scanning instead
# of one pass over the response. The baseline below is the same bytes in a single
# scan, so the ratio in this group is the amplification factor.


@pytest.mark.benchmark(group="stream-2kb-response")
def test_stream_baseline_single_scan(benchmark, bench_scanner: Scanner, clean_payloads) -> None:
    """Lower bound: the whole response scanned once, as `stream_holdback_chars` allows."""
    text = clean_payloads["2kb"]
    benchmark(bench_scanner.scan, text)
    record_bytes(benchmark, len(text.encode("utf-8")), chunks=1, overlap=0)


@pytest.mark.benchmark(group="stream-2kb-response")
@pytest.mark.parametrize("overlap", [0, 128, 512, DEFAULT_OVERLAP_CHARS])
def test_stream_chunked(benchmark, bench_scanner: Scanner, clean_payloads, overlap: int) -> None:
    """A 2 KiB response streamed as ~20-character deltas."""
    text = clean_payloads["2kb"]
    chunks = _deltas(text)

    def run() -> None:
        stream = StreamScanner(bench_scanner, overlap_chars=overlap)
        for chunk in chunks:
            stream.feed(chunk)

    benchmark(run)
    record_bytes(benchmark, len(text.encode("utf-8")), chunks=len(chunks), overlap=overlap)


@pytest.mark.benchmark(group="stream-delta-size")
@pytest.mark.parametrize("delta", [5, 20, 100, 500])
def test_stream_delta_size(benchmark, bench_scanner: Scanner, clean_payloads, delta: int) -> None:
    """Cost against delta size, at the default overlap.

    Smaller deltas mean more chunks over the same response, and the per-chunk
    overlap rescan makes the total superlinear in chunk count.
    """
    text = clean_payloads["2kb"]
    chunks = _deltas(text, delta)

    def run() -> None:
        stream = StreamScanner(bench_scanner, overlap_chars=DEFAULT_OVERLAP_CHARS)
        for chunk in chunks:
            stream.feed(chunk)

    benchmark(run)
    record_bytes(benchmark, len(text.encode("utf-8")), chunks=len(chunks), delta=delta)


@pytest.mark.benchmark(group="stream-hook-2kb")
def test_stream_hook_end_to_end(
    benchmark, guardrail: TrufflehogGuardrail, clean_payloads, bench_loop
) -> None:
    """The real hook, including async iteration over LiteLLM-shaped chunks."""
    chunks = [
        {"choices": [{"delta": {"content": piece}}]} for piece in _deltas(clean_payloads["2kb"])
    ]

    async def consume() -> int:
        async def source() -> Any:
            for chunk in chunks:
                yield chunk

        seen = 0
        async for _ in guardrail.async_post_call_streaming_iterator_hook(None, source(), {}):
            seen += 1
        return seen

    def run() -> int:
        return bench_loop.run_until_complete(consume())

    assert benchmark(run) == len(chunks)
    record_bytes(benchmark, len(clean_payloads["2kb"].encode("utf-8")), chunks=len(chunks))


# ---------------------------------------------------------------------------
# Async offload
# ---------------------------------------------------------------------------


@pytest.mark.benchmark(group="async-16kb")
def test_scan_sync(benchmark, bench_scanner: Scanner, clean_payloads) -> None:
    text = clean_payloads["16kb"]
    benchmark(bench_scanner.scan, text)
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="async-16kb")
def test_scan_async_offload(benchmark, bench_scanner: Scanner, clean_payloads, bench_loop) -> None:
    """`scan_async` hands off to a thread, which costs latency but frees the loop."""
    text = clean_payloads["16kb"]

    def run() -> Any:
        return bench_loop.run_until_complete(bench_scanner.scan_async(text))

    benchmark(run)
    record_bytes(benchmark, len(text.encode("utf-8")))


@pytest.mark.benchmark(group="async-concurrent-16kb")
@pytest.mark.parametrize("concurrency", [1, 4, 16])
def test_scan_async_concurrent(
    benchmark, bench_scanner: Scanner, clean_payloads, bench_loop, concurrency: int
) -> None:
    """Concurrent `scan_async` calls, as a busy proxy would issue them."""
    text = clean_payloads["16kb"]
    nbytes = len(text.encode("utf-8"))

    async def fanout() -> None:
        await asyncio.gather(*(bench_scanner.scan_async(text) for _ in range(concurrency)))

    def run() -> None:
        bench_loop.run_until_complete(fanout())

    benchmark(run)
    record_bytes(benchmark, nbytes * concurrency, concurrency=concurrency)


# ---------------------------------------------------------------------------
# Import and first-scan cost
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_scanner(native_available: bool) -> Iterator[Scanner]:
    s = Scanner(profile="core")
    yield s
    s.close()


@pytest.mark.benchmark(group="first-scan")
def test_first_scan_after_construction(benchmark, native_available: bool) -> None:
    """Construction plus the first scan: the cold cost a worker pays at startup.

    Worth knowing separately because `get_scanner` caches, so this is paid once
    while every subsequent request pays only the scan.
    """
    created: list[Scanner] = []

    def build_and_scan() -> None:
        s = Scanner(profile="core")
        created.append(s)
        s.scan("hello world, nothing to see here")

    try:
        benchmark.pedantic(build_and_scan, rounds=5, iterations=1, warmup_rounds=1)
    finally:
        for scanner in created:
            scanner.close()
