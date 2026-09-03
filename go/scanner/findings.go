package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// minCandidateLen is the shortest fragment worth locating. Anything shorter is
// noise (a version number, a separator) and masking it only mangles the text.
const minCandidateLen = 4

// minRepeatMaskLen is the shortest RawV2 fragment masked at *every* occurrence
// rather than one at a time.
//
// Whole credential values are always masked everywhere they appear, but the parts
// split out of RawV2 include hosts, ports and database names, and masking every
// occurrence of those would mangle the surrounding text. 12 bytes clears the
// common offenders - "postgresql" (10), "localhost" (9), "5432", "admin" - while
// still covering credential material such as a 40-byte AWS secret access key.
const minRepeatMaskLen = 12

// Span is a byte range in the scanned input: data[Start:End].
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Finding describes one detected secret.
//
// Spans locates every part of the credential found literally in the input, at
// every position it occurs. Multi-part credentials produce several: AWS reports
// Raw="AKIA..." and RawV2="AKIA...:wJalr...", so masking one span would leave the
// secret access key in place; a credential pasted twice likewise produces a span
// per copy. Spans is empty when a detector normalised or recombined its match
// (e.g. a rebuilt connection string); such a finding can only be blocked.
type Finding struct {
	DetectorType string `json:"detector_type"`
	DetectorName string `json:"detector_name,omitempty"`
	Description  string `json:"description,omitempty"`

	Verified          bool   `json:"verified"`
	VerificationError string `json:"verification_error,omitempty"`

	// Redacted is trufflehog's display-safe rendering, if the detector has one.
	Redacted string `json:"redacted,omitempty"`
	// SecretSHA256 identifies the credential without disclosing it.
	SecretSHA256 string `json:"secret_sha256"`

	Spans []Span `json:"spans"`

	// Raw is only populated when Config.IncludeRaw is set.
	Raw string `json:"raw,omitempty"`

	ExtraData map[string]string `json:"extra_data,omitempty"`

	// WordlistFalsePositive is set when trufflehog's wordlist check flagged
	// this unverified result. Only reachable when DropWordlistFPs is false.
	WordlistFalsePositive bool `json:"wordlist_false_positive,omitempty"`
}

// Redactable reports whether masking the spans fully removes the credential.
func (f Finding) Redactable() bool { return len(f.Spans) > 0 }

// Report is the result of a single scan.
type Report struct {
	Findings     []Finding `json:"findings"`
	ScannedBytes int       `json:"scanned_bytes"`
	DurationMS   float64   `json:"duration_ms"`
	// Truncated means input exceeded Config.MaxBytes and the tail was not scanned.
	Truncated bool `json:"truncated,omitempty"`
	// Errors holds non-fatal per-detector failures; such a scan may be incomplete.
	Errors []string `json:"errors,omitempty"`
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// candidate is a literal fragment to locate in the input.
type candidate struct {
	value []byte
	// whole marks a complete credential value as the detector reported it, as
	// opposed to a fragment split out of RawV2. Whole values are unambiguously
	// secret material, so every occurrence of one is masked.
	whole bool
}

// candidateSecrets returns the distinct literal fragments worth locating,
// longest first so a superset is matched before its parts.
//
// RawV2 is detector-composed: trufflehog joins multi-part credentials with ":",
// so RawV2 itself is usually absent from the input while its parts are present.
// Hence both RawV2 whole and each colon-separated part.
func candidateSecrets(primary string, raw, rawV2 []byte) []candidate {
	var out []candidate
	seen := make(map[string]struct{})

	add := func(b []byte, whole bool) {
		if len(b) < minCandidateLen {
			return
		}
		if _, ok := seen[string(b)]; ok {
			return
		}
		seen[string(b)] = struct{}{}
		out = append(out, candidate{value: b, whole: whole})
	}

	if primary != "" {
		add([]byte(primary), true)
	}
	add(raw, true)
	if len(rawV2) > 0 && !bytes.Equal(rawV2, raw) {
		add(rawV2, true)
		for _, part := range bytes.Split(rawV2, []byte(":")) {
			add(part, false)
		}
	}
	return out
}

// offsetTracker locates occurrences of credential fragments in the scanned input.
//
// A whole credential value is located at every occurrence, because redaction has
// to be driven by what the text contains rather than by how many results a
// detector returned: several detectors deduplicate identical results internally
// (OpenAI does), so counting results would leave the second copy of a pasted
// credential in place.
//
// Short RawV2 fragments keep the older one-at-a-time behaviour, tracked per
// (detector, fragment) pair: two detectors finding the same secret must both
// report the first occurrence, while one detector reporting it twice means the
// input contains it twice.
type offsetTracker struct {
	data []byte
	next map[string]int
}

func newOffsetTracker(data []byte) *offsetTracker {
	return &offsetTracker{data: data, next: make(map[string]int)}
}

// locate finds the next unclaimed occurrence of secret, or (-1,-1) if there is none.
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

// locateAll finds every occurrence of secret, independent of tracker state.
func (t *offsetTracker) locateAll(secret []byte) []Span {
	if len(secret) < minCandidateLen {
		return nil
	}
	var spans []Span
	for from := 0; from+len(secret) <= len(t.data); {
		idx := bytes.Index(t.data[from:], secret)
		if idx < 0 {
			break
		}
		start := from + idx
		spans = append(spans, Span{Start: start, End: start + len(secret)})
		from = start + len(secret)
	}
	return spans
}

// spansFor locates every candidate fragment and returns merged, non-overlapping
// spans sorted by start offset.
func (t *offsetTracker) spansFor(detectorKey string, candidates []candidate) []Span {
	var spans []Span
	for _, c := range candidates {
		if c.whole || len(c.value) >= minRepeatMaskLen {
			spans = append(spans, t.locateAll(c.value)...)
			continue
		}
		start, end := t.locate(detectorKey, c.value)
		if start < 0 {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return mergeSpans(spans)
}

// mergeSpans sorts by start offset and coalesces overlapping or adjacent ranges.
func mergeSpans(spans []Span) []Span {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End > spans[j].End
	})
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
