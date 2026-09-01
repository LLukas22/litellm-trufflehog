package scanner

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	thconfig "github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// Defaults applied by Config.withDefaults.
const (
	DefaultMaxBytes          = 1 << 20 // 1 MiB
	DefaultDetectorTimeoutMS = 2000
)

// Config controls detector selection and scan behaviour. It is the JSON
// contract between the Python wrapper and the Go core, so field tags are
// part of the public API.
type Config struct {
	// Profile selects the base detector set: "minimal", "core" or "all".
	// Defaults to "core".
	Profile string `json:"profile"`

	// IncludeDetectors adds detectors on top of the profile. Values use
	// trufflehog's own syntax: case-insensitive enum names ("AWS"), numeric
	// IDs ("2"), versions ("Github.v2") or ranges ("1-10").
	IncludeDetectors []string `json:"include_detectors"`

	// ExcludeDetectors removes detectors, applied after IncludeDetectors.
	// Same syntax as IncludeDetectors.
	ExcludeDetectors []string `json:"exclude_detectors"`

	// Verify enables live credential verification. This sends candidate
	// secrets to third-party APIs (AWS, GitHub, ...) and adds network
	// latency. Off by default, and it should stay off unless the operator
	// has explicitly accepted that trade-off.
	Verify bool `json:"verify"`

	// FilterEntropy drops unverified results below this Shannon entropy.
	// Zero disables the filter.
	FilterEntropy float64 `json:"filter_entropy"`

	// FilterUnverified keeps only the first unverified result per detector
	// per match (trufflehog's detectors.CleanResults behaviour).
	FilterUnverified bool `json:"filter_unverified"`

	// DropWordlistFPs discards unverified results that trufflehog's wordlist
	// check flags as false positives. Enabled unless explicitly disabled.
	DropWordlistFPs *bool `json:"drop_wordlist_fps"`

	// ScanEntireChunk passes the whole input to each matching detector
	// instead of a window around the matched keyword. Slower, but catches
	// credentials whose parts are far apart.
	ScanEntireChunk bool `json:"scan_entire_chunk"`

	// DetectorTimeoutMS bounds a single detector invocation. Defaults to 2000.
	DetectorTimeoutMS int `json:"detector_timeout_ms"`

	// Concurrency bounds parallel detector invocations. Defaults to NumCPU.
	Concurrency int `json:"concurrency"`

	// IncludeRaw includes the raw secret in findings. Off by default: the
	// point of this package is to stop secrets propagating, so echoing them
	// back into logs or HTTP responses defeats it. Intended for tests only.
	IncludeRaw bool `json:"include_raw"`

	// MaxBytes truncates input before scanning. Defaults to 1 MiB.
	MaxBytes int `json:"max_bytes"`

	// SkipWarmup disables the one-time detector warm-up performed by New.
	// Warm-up trades a little construction time for deterministic first-request
	// behaviour, so leave it on unless you are measuring startup cost.
	SkipWarmup bool `json:"skip_warmup"`
}

// ParseConfig decodes a JSON config, rejecting unknown fields so typos in
// proxy configuration surface as errors instead of being silently ignored.
func ParseConfig(data []byte) (Config, error) {
	cfg := Config{}
	if len(data) == 0 {
		return cfg.withDefaults(), nil
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("invalid scanner config: %w", err)
	}
	return cfg.withDefaults(), nil
}

func (c Config) withDefaults() Config {
	if c.Profile == "" {
		c.Profile = DefaultProfile
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.DetectorTimeoutMS <= 0 {
		c.DetectorTimeoutMS = DefaultDetectorTimeoutMS
	}
	if c.Concurrency <= 0 {
		c.Concurrency = runtime.NumCPU()
	}
	if c.DropWordlistFPs == nil {
		t := true
		c.DropWordlistFPs = &t
	}
	return c
}

func (c Config) detectorTimeout() time.Duration {
	return time.Duration(c.DetectorTimeoutMS) * time.Millisecond
}

func (c Config) dropWordlistFPs() bool {
	return c.DropWordlistFPs == nil || *c.DropWordlistFPs
}

// parseDetectorIDs converts a slice of user-supplied detector selectors into a
// set of trufflehog DetectorIDs.
func parseDetectorIDs(selectors []string) (map[thconfig.DetectorID]struct{}, error) {
	out := make(map[thconfig.DetectorID]struct{})
	if len(selectors) == 0 {
		return out, nil
	}
	ids, err := thconfig.ParseDetectors(strings.Join(selectors, ","))
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out, nil
}

// inSet reports whether a detector is selected by a DetectorID set. A set entry
// with Version 0 means "every version of this detector type", which mirrors
// trufflehog's own engine semantics so that e.g. "Github" selects both
// github/v1 and github/v2.
func inSet(d detectors.Detector, set map[thconfig.DetectorID]struct{}) bool {
	key := thconfig.GetDetectorID(d)
	if _, ok := set[key]; ok {
		return true
	}
	if key.Version == 0 {
		return false
	}
	key.Version = 0
	_, ok := set[key]
	return ok
}

// resolveDetectors builds the effective detector list: profile, plus includes,
// minus excludes.
func resolveDetectors(cfg Config) ([]detectors.Detector, error) {
	names, err := profileNames(cfg.Profile)
	if err != nil {
		return nil, err
	}
	selected, err := parseDetectorIDs(names)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", cfg.Profile, err)
	}

	includes, err := parseDetectorIDs(cfg.IncludeDetectors)
	if err != nil {
		return nil, fmt.Errorf("include_detectors: %w", err)
	}
	for id := range includes {
		selected[id] = struct{}{}
	}

	excludes, err := parseDetectorIDs(cfg.ExcludeDetectors)
	if err != nil {
		return nil, fmt.Errorf("exclude_detectors: %w", err)
	}

	all := defaults.DefaultDetectors()
	out := make([]detectors.Detector, 0, len(all))
	for _, d := range all {
		if !inSet(d, selected) {
			continue
		}
		if len(excludes) > 0 && inSet(d, excludes) {
			continue
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("detector selection resolved to zero detectors")
	}
	return out, nil
}
