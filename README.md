# litellm-trufflehog

Simple & fast [trufflehog](https://github.com/trufflesecurity/trufflehog) secrets scanning for
[LiteLLM](https://github.com/BerriAI/litellm).

Wraps trufflehog's detection engine as a Go shared library and exposes it to Python, plus a
LiteLLM guardrail that blocks or redacts credentials in prompts and model responses.

```python
from litellm_trufflehog import Scanner

with Scanner() as scanner:
    report = scanner.scan("deploy with ghp_R2d2c3PoAb7Yx1Qz9Kv4Nm6Ht8Jw5Lp3Sd0")
    if report:
        print(report.summary())
        # {'secrets_detected': 1, 'detectors': ['Github'], 'verified': 0, ...}
```

## Why not just run the trufflehog CLI?

Scanning happens on the request path, so process-per-request is not viable. This links
trufflehog's detector engine directly:

Median latency of `Scanner.scan()` measured from Python with `just bench-py`, `core` profile
(128 detectors), i7-1270P. These are end-to-end figures: the ctypes call, the scan, JSON
decoding and object construction.

| Input | Latency | Throughput |
|---|---|---|
| Chat turn (256 B) | **9 µs** | — |
| Prompt (2 KiB) | **15 µs** | 103 MB/s |
| RAG context (16 KiB) | **90 µs** | 157 MB/s |
| Large paste (128 KiB) | **818 µs** | 149 MB/s |
| 16 KiB *mentioning* credentials | 544 µs | 28 MB/s |
| 16 KiB *containing* a credential | 210 µs | 69 MB/s |
| Scanner construction | 1.5 ms (`all`: 6 ms) | one-off per worker |

The fast path is an Aho-Corasick keyword prefilter over the selected detectors: text with no
credential-shaped keywords returns immediately without running a single regex. Prose that
merely *talks about* API keys defeats that prefilter and costs ~6x more, which is the case to
size for if you proxy a coding assistant. Choosing `all` over `core` only costs ~30% on clean
text, because the prefilter absorbs most of the difference.

The Python wrapper is not the bottleneck: JSON decoding plus object construction is ~8 µs of
the 90 µs at 16 KiB, and encoding the input is 0.3 µs.

Notably this does **not** use trufflehog's `engine.Engine`, which is built for source
enumeration — it requires a `SourceManager` and starts four pools of worker goroutines with
`NumCPU`-sized channels. Only the detection core it wraps is needed here, used synchronously.

## Install

Wheels are `py3-none-manylinux_2_28_x86_64`: platform-specific because of the shared library,
but **not** tied to a CPython ABI, so one wheel works on every CPython 3.10+.

```bash
uv pip install litellm-trufflehog
```

Building from source needs Go 1.25+ and a C compiler (cgo). See [Development](#development).

## Use as a LiteLLM guardrail

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

A full example is in [`examples/config.yaml`](examples/config.yaml). A blocked request gets an
HTTP 400 whose body names detectors and counts only:

```json
{
  "error": "secret_detected",
  "message": "Blocked: 1 secret(s) detected in the request by trufflehog (Github).",
  "input_type": "request",
  "secrets_detected": 1,
  "detectors": ["Github"],
  "verified": 0,
  "truncated": false,
  "degraded": false,
  "scan_errors": [],
  "scanned_bytes": 44
}
```

The secret itself is never echoed into an error body or a log line — doing so is a common way
to turn one leak into several.

### Guardrail options

| Option | Default | Meaning |
|---|---|---|
| `on_detection` | `block` | `block`, `redact` or `log` |
| `profile` | `core` | `minimal`, `core` or `all` |
| `detectors` | – | Extra detectors, trufflehog selector syntax |
| `exclude_detectors` | – | Detectors to drop |
| `verify` | `false` | Live-verify credentials (**see warning**) |
| `max_bytes` | `1 MiB` | Truncation limit per text |
| `block_on_truncation` | `true` | Block when input exceeded `max_bytes` |
| `block_on_scan_error` | `true` | Block when a detector failed |
| `filter_entropy` | `0` | Drop unverified results below this Shannon entropy |
| `filter_unverified` | `false` | Keep only the first unverified result per detector |
| `drop_wordlist_fps` | `true` | Apply trufflehog's wordlist false-positive filter |
| `scan_entire_chunk` | `false` | Pass whole input to detectors instead of a keyword window |
| `stream_holdback_chars` | `4096` | Trailing characters LiteLLM withholds while streaming |

### Streaming

A secret can straddle two streamed chunks (`ghp_abc` / `def…`), which per-chunk scanning would
miss. The guardrail returns `stream_holdback_chars` from `apply_guardrail`, so LiteLLM withholds
a trailing window and a match is never split. For the
`async_post_call_streaming_iterator_hook` path there is a `StreamScanner` that keeps a 3 KiB
overlap (matching trufflehog's own `DefaultPeekSize`) and reports each secret exactly once.

Note that terminating a stream can only stop *further* content: chunks already yielded have been
delivered. Use `mode: pre_call` for prompts, where blocking is absolute.

**Prefer the holdback path on cost grounds too.** `StreamScanner` rescans a window per chunk, so
its cost tracks the *number of chunks*, not the size of the response. A 2 KiB response scanned
once takes 15 µs; fed as 20-character deltas it takes 1.3 ms, and as 5-character deltas 5.5 ms —
roughly 80x and 300x. Shrinking `overlap_chars` barely helps (0 and 3072 measure the same),
because the cost is per-call overhead rather than rescanned bytes. If you must use the iterator
hook, accumulate deltas and feed larger blocks: at 500-character blocks the same response costs
68 µs.

## Detector profiles

trufflehog ships ~858 detectors. Enabling all of them costs latency and, more importantly,
false positives, so the default is a curated set.

| Profile | Detectors | Contents |
|---|---|---|
| `minimal` | ~34 | Cloud, source control, private keys/JWTs, LLM provider keys |
| `core` *(default)* | ~128 | `minimal` + CI, registries, databases, secret managers, payments, identity, observability |
| `all` | ~858 | Everything trufflehog ships |

`Generic` — trufflehog's catch-all high-entropy detector and by far the largest source of false
positives — is in **no** profile. Enable it explicitly if you want it:

```yaml
detectors: ["Generic"]
```

Selector syntax is trufflehog's own: names (`AWS`), IDs (`2`), versions (`Github.v2`) and ranges
(`1-10`). A test asserts every curated name still matches a shipped detector, so a dependency
bump cannot silently reduce coverage.

## ⚠️ Verification is off by default

`verify: true` makes trufflehog call the credential's provider to check whether it is live. That
means:

- **The candidate secret is transmitted to a third party** (AWS, GitHub, Slack, …).
- Provider latency is added to any request containing a match.
- Providers may log, rate-limit or alert on the attempt.

Detection is entirely regex/keyword based and needs none of this. Only enable verification if
you specifically want to distinguish live credentials from dead ones and accept the above.

## Fail-closed behaviour

An empty report can mean "nothing found" *or* "we did not manage to look". These are not the
same, and conflating them fails open exactly when scanning is broken. So:

- A detector that panics or times out is recorded in `report.errors`; `report.degraded` is then
  true and the guardrail **blocks** by default (`block_on_scan_error`).
- Input beyond `max_bytes` is not scanned; `report.truncated` is set and the guardrail
  **blocks** by default (`block_on_truncation`).
- If a secret cannot be located in the text it cannot be masked, so `redact` **refuses** and
  falls back to blocking rather than forwarding partially-masked text.

## Redaction

```python
masked, report = scanner.redact("id=AKIA… secret=wJalr…")
# 'id=[REDACTED:AWS] secret=[REDACTED:AWS]'
```

Two details that are easy to get wrong and are covered by tests:

- **Multi-part credentials.** The AWS detector reports `Raw` as the key ID and `RawV2` as
  `"key-id:secret"`, and `RawV2` never appears literally in the text. Masking one span would
  leave the secret access key in place, so every locatable part gets its own span.
- **Byte offsets, not code points.** Offsets index the UTF-8 encoding. Slicing a `str` with them
  would shift every cut point by the extra bytes in any preceding non-ASCII text, mangling the
  output and potentially leaving part of the secret behind.

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
```

`scan_async` offloads to a thread; ctypes releases the GIL for the duration of the native call,
so concurrent scans genuinely run in parallel.

Findings carry `secret_sha256` rather than the secret. `include_raw=True` exists for tests and
is not reachable from guardrail configuration.

## Known limitations

- **Base64/UTF-16 decoding is not enabled.** trufflehog can find secrets inside encoded blobs,
  but a finding in decoded bytes has no offset in the original text, so it could be blocked but
  never redacted. Deferred rather than shipped half-working.
- **The wordlist filter can discard real secrets.** trufflehog drops unverified matches
  containing a dictionary word or placeholder term (`example`, `abcde`, …). This is upstream
  default behaviour; set `drop_wordlist_fps: false` to keep them.
- **The shared library is large**: ~74 MB stripped (~145 MB unstripped), because trufflehog's
  dependency tree pulls in the AWS SDK, go-git, a WASM runtime and the Docker client. The wheel
  is correspondingly large.
- **Linux x86_64 only** for prebuilt wheels.

## Development

Requires [`just`](https://github.com/casey/just), [`uv`](https://github.com/astral-sh/uv),
Go 1.25+ and a C compiler.

```bash
just build      # compile the Go shared library into the package
just sync       # create the venv from uv.lock
just check      # go vet + ruff + ty + all tests
just test-go    # Go tests only
just bench      # both benchmark suites
just bench-py   # Python benchmarks: latency and throughput as a caller sees them
just bench-go   # Go benchmarks: the scanner in isolation
just wheel      # release manylinux wheel in Docker -> ./dist
```

Benchmarks are skipped by default during `just check`, and the Python suite prints a
latency/throughput table. `just bench-save` and `just bench-compare` diff against a baseline.

A C compiler is needed for cgo. `gcc`/`clang` on Linux and macOS; on Windows use mingw-w64
(`winget install BrechtSanders.WinLibs.POSIX.UCRT`) — MSVC does not work with cgo.

Layout:

```
go/scanner/     detector selection, scanning, span/offset logic  (pure Go, unit tested)
go/cbind/       C shared-library bridge (handles, JSON in/out)
src/litellm_trufflehog/
  _lib.py       ctypes binding
  scanner.py    Scanner, ScanReport, Finding, redaction
  stream.py     overlapping-window scanner for streams
  guardrail.py  LiteLLM CustomGuardrail
```

## License

**AGPL-3.0-or-later.** trufflehog is AGPL-3.0 and is linked into the shared library, making this
package a derivative work.

This matters more than usual here, because a LiteLLM proxy is a *network service*: under AGPL
§13, users interacting with it over a network must be offered the corresponding source. If you
deploy this in a service you do not intend to open-source, take advice before doing so.
