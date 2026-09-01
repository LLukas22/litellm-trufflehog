package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// minCandidateLen is the shortest credential fragment we will try to locate.
// Anything shorter is noise (a version number, a separator) and masking it
// would mangle the surrounding text for no security benefit.
const minCandidateLen = 4

// Span is a byte range in the scanned input: data[Start:End].
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Finding describes one detected secret.
//
// Spans locates every part of the credential that could be found literally in
// the input. Multi-part credentials produce multiple spans: the AWS detector,
// for example, reports Raw="AKIA..." and RawV2="AKIA...:wJalr...", so masking a
// single span would leave the secret access key in place.
//
// Spans may be empty when a detector normalises or recombines what it matched
// (e.g. a URI detector rebuilding a connection string). Such a finding cannot
// be redacted, only blocked - see Redactable.
type Finding struct {
	DetectorType string `json:"detector_type"`
	DetectorName string `json:"detector_name,omitempty"`
	Description  string `json:"description,omitempty"`

	Verified          bool   `json:"verified"`
	VerificationError string `json:"verification_error,omitempty"`

	// Redacted is trufflehog's display-safe rendering, when the detector
	// provides one.
	Redacted string `json:"redacted,omitempty"`
	// SecretSHA256 identifies the credential without disclosing it, so
	// findings can be deduplicated and logged safely.
	SecretSHA256 string `json:"secret_sha256"`

	Spans []Span `json:"spans"`

	// Raw is only populated when Config.IncludeRaw is set.
	Raw string `json:"raw,omitempty"`

	ExtraData map[string]string `json:"extra_data,omitempty"`

	// WordlistFalsePositive is set when trufflehog's wordlist check flagged
	// this unverified result. Only reachable when DropWordlistFPs is false.
	WordlistFalsePositive bool `json:"wordlist_false_positive,omitempty"`
}

// Redactable reports whether every part of this credential was located, and so
// whether masking the spans fully removes it from the input.
func (f Finding) Redactable() bool { return len(f.Spans) > 0 }

// Report is the result of a single scan.
type Report struct {
	Findings     []Finding `json:"findings"`
	ScannedBytes int       `json:"scanned_bytes"`
	DurationMS   float64   `json:"duration_ms"`
	// Truncated is set when input exceeded Config.MaxBytes; the tail was not
	// scanned.
	Truncated bool `json:"truncated,omitempty"`
	// Errors holds non-fatal per-detector failures (timeouts, transport
	// errors). A scan reporting errors may be incomplete.
	Errors []string `json:"errors,omitempty"`
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// candidateSecrets returns the distinct literal fragments worth locating for a
// result, longest first so that a superset is matched before its parts.
//
// RawV2 is a detector-composed value: trufflehog builds multi-part credentials
// by joining parts with ":" (see the AWS access-key detector), so RawV2 itself
// is usually absent from the input while its parts are present. We therefore
// try RawV2 whole, and also each colon-separated part.
func candidateSecrets(primary string, raw, rawV2 []byte) [][]byte {
	var out [][]byte
	seen := make(map[string]struct{})

	add := func(b []byte) {
		if len(b) < minCandidateLen {
			return
		}
		if _, ok := seen[string(b)]; ok {
			return
		}
		seen[string(b)] = struct{}{}
		out = append(out, b)
	}

	if primary != "" {
		add([]byte(primary))
	}
	add(raw)
	if len(rawV2) > 0 && !bytes.Equal(rawV2, raw) {
		add(rawV2)
		for _, part := range bytes.Split(rawV2, []byte(":")) {
			add(part)
		}
	}
	return out
}

// offsetTracker locates successive occurrences of credential fragments within
// the scanned input.
//
// Occurrences are tracked per (detector, fragment) pair: two different
// detectors finding the same secret must both report the first occurrence,
// while one detector reporting the same secret twice means the input genuinely
// contains it twice and each report should get its own span.
type offsetTracker struct {
	data []byte
	next map[string]int
}

func newOffsetTracker(data []byte) *offsetTracker {
	return &offsetTracker{data: data, next: make(map[string]int)}
}

// locate finds the next unclaimed occurrence of secret, or (-1,-1) if the
// fragment is absent or every occurrence has already been claimed.
func (t *offsetTracker) locate(detectorKey string, secret []byte) (int, int) {
	if len(secret) < minCandidateLen {
		return -1, -1
	}
	key := detectorKey + "\x00" + string(secret)
	from := t.next[key]
	if from > len(t.data) {
		return -1, -1
	}
	idx := bytes.Index(t.data[from:], secret)
	if idx < 0 {
		return -1, -1
	}
	start := from + idx
	end := start + len(secret)
	t.next[key] = end
	return start, end
}

// spansFor locates every candidate fragment and returns non-overlapping spans
// sorted by start offset. Overlaps are merged so that a fragment contained in
// an already-claimed larger fragment does not produce a nested span.
func (t *offsetTracker) spansFor(detectorKey string, candidates [][]byte) []Span {
	var spans []Span
	for _, c := range candidates {
		start, end := t.locate(detectorKey, c)
		if start < 0 {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return mergeSpans(spans)
}

// mergeSpans sorts spans by start offset and coalesces overlapping or adjacent
// ranges.
func mergeSpans(spans []Span) []Span {
	if len(spans) < 2 {
		return spans
	}
	// Insertion sort: span counts are tiny (one per credential part).
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j].Start < spans[j-1].Start; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}
	out := []Span{spans[0]}
	for _, s := range spans[1:] {
		last := &out[len(out)-1]
		if s.Start <= last.End {
			if s.End > last.End {
				last.End = s.End
			}
			continue
		}
		out = append(out, s)
	}
	return out
}
