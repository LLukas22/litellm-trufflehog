# litellm-trufflehog

[![PyPI](https://img.shields.io/pypi/v/litellm-trufflehog)](https://pypi.org/project/litellm-trufflehog/)
[![Python](https://img.shields.io/pypi/pyversions/litellm-trufflehog)](https://pypi.org/project/litellm-trufflehog/)

Fast [trufflehog](https://github.com/trufflesecurity/trufflehog) secret scanning for
[LiteLLM](https://github.com/BerriAI/litellm). trufflehog's detector engine is compiled into a Go
shared library and called from Python via ctypes.

## Install

```bash
uv pip install litellm-trufflehog
```

Wheels are `py3-none-manylinux_2_28_x86_64`: platform-specific, but ABI-independent, so one wheel
works on every CPython 3.10+. Building from source needs Go 1.25+ and a C compiler (cgo).

## Use in LiteLLM

```yaml
guardrails:
  - guardrail_name: trufflehog
    litellm_params:
      guardrail: litellm_trufflehog.TrufflehogGuardrail
      mode: pre_call          # required for redaction
      default_on: true
      on_detection: block
      profile: core
```

Full example: [`examples/config.yaml`](examples/config.yaml). A blocked request gets HTTP 400 whose
body names detectors and counts only, never the secret.

| Option | Default | Meaning |
|---|---|---|
| `on_detection` | `block` | `block`, `redact` or `log` |
| `profile` | `core` | `minimal` (~34 detectors), `core` (~128), `all` (~858) or `paranoid` (~859) |
| `detectors` | – | Extra detectors, trufflehog selector syntax (`AWS`, `Github.v2`, `1-10`), plus `HighEntropy` |
| `exclude_detectors` | – | Detectors to drop |
| `verify` | `false` | Live-verify credentials: **transmits candidates to third parties** |
| `max_bytes` | `1 MiB` | Truncation limit per text |
| `block_on_truncation` | `true` | Block when input exceeded `max_bytes` |
| `block_on_scan_error` | `true` | Block when a detector failed |
| `filter_entropy` | `0` | Drop unverified results below this Shannon entropy |
| `filter_unverified` | `false` | Keep only the first unverified result per detector |
| `drop_wordlist_fps` | `true` | Apply trufflehog's wordlist false-positive filter |
| `scan_entire_chunk` | `false` | Pass whole input to detectors instead of a keyword window |
| `stream_holdback_chars` | `4096` | Trailing characters LiteLLM withholds while streaming |

Notes:

- **Fails closed.** A truncated input or a failed detector blocks by default, because an empty
  report can also mean "we did not manage to look". `redact` falls back to blocking when a secret
  cannot be located.
- **Catch-alls are opt-in**, being the largest source of false positives, and their matches can
  swallow a neighbouring character, so prefer `block` or `log` over `redact`. `HighEntropy` flags
  high-entropy values near `pass`/`token`/`cred`/`secret`/`key`, and is what `profile: paranoid`
  adds. trufflehog's own `Generic` is available unchanged as `detectors: ["Generic"]`.
- **Streaming** is handled by the `stream_holdback_chars` tail, so a secret cannot be split across
  chunks. Use `mode: pre_call` for prompts, where blocking is absolute.

## Performance

Median `Scanner.scan()` latency measured from Python (`just bench-py`), `core` profile,
i7-1270P. End-to-end: ctypes call, scan, JSON decode, object construction.

| Input | Latency | Throughput |
|---|---|---|
| Chat turn (256 B) | **9 µs** | — |
| Prompt (2 KiB) | **15 µs** | 103 MB/s |
| RAG context (16 KiB) | **90 µs** | 157 MB/s |
| Large paste (128 KiB) | **818 µs** | 149 MB/s |
| 16 KiB *mentioning* credentials | 544 µs | 28 MB/s |
| 16 KiB *containing* a credential | 210 µs | 69 MB/s |
| Scanner construction | 1.5 ms (`all`: 6 ms) | one-off per worker |

An Aho-Corasick keyword prefilter means clean text runs no regexes at all. Prose that merely
*talks about* API keys defeats it and costs ~6x more. `all` over `core` costs only ~30% on clean
text.

## Python API

```python
from litellm_trufflehog import Scanner, StreamScanner, get_scanner

scanner = get_scanner(profile="core")     # process-wide cache; construction is the costly part
report = scanner.scan(text)               # or: await scanner.scan_async(text)

bool(report)              # anything detected?
report.detector_types     # ('AWS', 'Github') - safe to log
report.summary()          # log/response-safe dict, no secret material
report.degraded           # a detector failed; an empty result is not trustworthy
report.trustworthy        # complete scan, no failures
report.fully_redactable   # every finding could be located

for finding in report:
    finding.detector_type, finding.secret_sha256, finding.spans, finding.verified

masked, report = scanner.redact("id=AKIA… secret=wJalr… again=AKIA…")
# 'id=[REDACTED:AWS:9f2c1a04] secret=[REDACTED:AWS:be70d3f1] again=[REDACTED:AWS:9f2c1a04]'
```

Spans are UTF-8 byte offsets; findings carry `secret_sha256`, not the secret. `scan_async` offloads
to a thread, and ctypes releases the GIL, so concurrent scans run in parallel.

Redaction masks *every* occurrence of a value, and each placeholder ends in a per-process keyed
fingerprint, so equal tags mean the same credential twice. Pass `template=` to `redact()` to change
the format (`{detector}` and `{fingerprint}`, both optional).

`StreamScanner` covers the `async_post_call_streaming_iterator_hook` path, but prefer the holdback
path: its cost tracks chunk *count*, so a 2 KiB response costs 15 µs scanned once but 1.3 ms as
20-character deltas.

## Development

Requires [`just`](https://github.com/casey/just), [`uv`](https://github.com/astral-sh/uv), Go 1.25+
and a C compiler for cgo (`gcc`/`clang`; on Windows use mingw-w64 —
`winget install BrechtSanders.WinLibs.POSIX.UCRT` — MSVC does not work with cgo).

```bash
just build      # compile the Go shared library into the package
just sync       # create the venv from uv.lock
just check      # go vet + ruff + ty + all tests
just bench      # both benchmark suites (bench-py / bench-go individually)
just wheel      # release manylinux wheel in Docker -> ./dist
```

```
go/scanner/     detector selection, scanning, span/offset logic  (pure Go, unit tested)
go/cbind/       C shared-library bridge (handles, JSON in/out)
src/litellm_trufflehog/
  _lib.py       ctypes binding
  scanner.py    Scanner, ScanReport, Finding, redaction
  stream.py     overlapping-window scanner for streams
  guardrail.py  LiteLLM CustomGuardrail
```

Known limitations: no base64/UTF-16 decoding (a finding in decoded bytes has no offset in the
original text); the wordlist filter can discard real secrets; the shared library is ~74 MB
stripped, because trufflehog pulls in the AWS SDK, go-git, a WASM runtime and the Docker client;
prebuilt wheels are Linux x86_64 only.

AGPL-3.0-or-later, because trufflehog is linked in. Note that a LiteLLM proxy is a network service:
under AGPL §13 its users must be offered the corresponding source.
