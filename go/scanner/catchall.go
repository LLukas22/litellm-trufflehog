package scanner

import (
	"context"
	"strings"

	re2 "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// catchAllSelector is the name that selects the detector below, in a profile or
// in Config.IncludeDetectors / Config.ExcludeDetectors.
//
// It is an alias resolved by parseDetectorIDs rather than a trufflehog detector
// name, because the protobuf enum has no slot for detectors that upstream does
// not ship; the underlying DetectorType is CustomRegex.
const catchAllSelector = "HighEntropy"

// catchAllMinEntropy is the Shannon entropy a candidate must reach.
//
// It replaces part of what trufflehog's base64 rule did by accident: measured
// over real credentials this sits far below them (4.05-4.70 bits for provider
// keys, database passwords and Entra secrets) and above padding such as
// "0000000000000000" or "aaaa1111aaaa1111".
const catchAllMinEntropy = 3.0

// Trimmed from both ends of a candidate before it is reported, as trufflehog's
// Generic detector does: the window regex happily includes surrounding quotes,
// brackets and punctuation.
const catchAllTrimCutset = "`\" '.,)(][}{"

// catchAllKeywords feed the Aho-Corasick prefilter, so text without any of them
// costs nothing. Same set as trufflehog's Generic detector.
var catchAllKeywords = []string{"pass", "token", "cred", "secret", "key"}

// catchAllExcludePatterns are trufflehog's Generic exclusions, with one change:
// the hex rule covers every digest length rather than only 64 characters.
//
// Upstream rejects 64-character hex explicitly and catches shorter digests only
// as a side effect of dropping anything that base64-decodes - md5 (32) and sha1
// (40) are both a multiple of four characters. Dropping the base64 rule without
// widening this one would start reporting every git commit SHA, checksum and
// image digest in a prompt, which measured as five false positives on a corpus
// where the fixed detector reports none.
var catchAllExcludePatterns = []string{
	`[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}`,                                    // UUID
	`[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}`, // UUIDv4
	`[A-Z]{2,6}\-[0-9]{2,6}`, // issue tracker
	`#[a-fA-F0-9]{6}\b`,      // hex colour
	`\b[A-Fa-f0-9]{32,}\b`,   // hex digest: md5, sha1, sha256, image digests
	`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`, // URL
	`\b([/]{0,1}([\w]+[/])+[\w\.]*)\b`,                 // file path
	`([0-9A-F]{2}[:-]){5}([0-9A-F]{2})`,                // MAC address
	`\d{4}[-/]{1}([0]\d|1[0-2])[-/]{1}([0-2]\d|3[01])`, // date
	`[v|\-]\d\.\d`, // version
	`\d\.\d\.\d-`,  // version
	`[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}`,      // IP or OID
	`[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}`, // hex encoding
	`[\w]+\([\w, ]+\)`, // function call
}

// catchAllDetector reports high-entropy values assigned to credential-like
// names: the credentials no provider-specific detector can recognise, such as an
// internal service token or a proxy's own API key.
//
// It exists because trufflehog's Generic detector discards every candidate that
// base64-decodes (pkg/detectors/generic/generic.go, "toss any that b64 decode"),
// which silently covers any alphanumeric token whose length is a multiple of four
// - a very common shape for issued API keys. That check cannot be bypassed from
// outside, since it runs inside FromData.
//
// Deliberately kept as a separate detector rather than a replacement for Generic,
// so that asking for trufflehog's Generic still gets trufflehog's behaviour.
//
// Unlike trufflehog's own custom-regex detectors this does not implement
// CustomFalsePositiveChecker, so the wordlist false-positive filter still applies
// to its results - that is what rejects candidates like "postgres_password".
type catchAllDetector struct {
	keyPat  *re2.Regexp
	exclude []*re2.Regexp
}

// Ensure the detector satisfies the interface at compile time.
var _ detectors.Detector = (*catchAllDetector)(nil)

// newCatchAllDetector compiles the patterns once per scanner.
//
// Compilation is deliberately not done in a package-level var: go-re2 spins up a
// wazero runtime on first use, and Scanner.warm exists to surface that failure as
// a warm-up error instead of a panic while loading the library.
func newCatchAllDetector() *catchAllDetector {
	d := &catchAllDetector{
		keyPat:  re2.MustCompile(detectors.PrefixRegex(catchAllKeywords) + `(\b[\x21-\x7e]{16,64}\b)`),
		exclude: make([]*re2.Regexp, 0, len(catchAllExcludePatterns)),
	}
	for _, pat := range catchAllExcludePatterns {
		d.exclude = append(d.exclude, re2.MustCompile(pat))
	}
	return d
}

func (d *catchAllDetector) Keywords() []string { return catchAllKeywords }

func (d *catchAllDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

func (d *catchAllDetector) Description() string {
	return "High-entropy value assigned to a credential-like name. litellm-trufflehog's " +
		"own catch-all: like trufflehog's Generic detector, but it keeps base64-shaped " +
		"values and rejects hex digests and low-entropy strings instead."
}

func (d *catchAllDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result

	for _, match := range d.keyPat.FindAllStringSubmatch(string(data), -1) {
		token := match[1]

		// Cheapest filters first, as trufflehog does: patterns over the match as
		// found, then the trim, then entropy over what would be reported.
		if d.excluded(token) {
			continue
		}
		token = strings.Trim(token, catchAllTrimCutset)
		if len(token) < minCandidateLen {
			continue
		}
		if detectors.StringShannonEntropy(token) < catchAllMinEntropy {
			continue
		}

		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_CustomRegex,
			DetectorName: catchAllSelector,
			Raw:          []byte(token),
		})
	}
	return results, nil
}

func (d *catchAllDetector) excluded(token string) bool {
	for _, re := range d.exclude {
		if re.MatchString(token) {
			return true
		}
	}
	return false
}
