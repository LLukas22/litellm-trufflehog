package scanner

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	thconfig "github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/generic"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// Defaults applied by Config.withDefaults.
const (
	DefaultMaxBytes          = 1 << 20 // 1 MiB
	DefaultDetectorTimeoutMS = 2000
)

// Config controls detector selection and scan behaviour. It is the JSON contract
// between the Python wrapper and the Go core, so the field tags are public API.
type Config struct {
	// Profile is the base detector set: "minimal", "core" (default), "all" or
	// "paranoid".
	Profile string `json:"profile"`

	// IncludeDetectors adds detectors on top of the profile, using trufflehog's
	// syntax: names ("AWS"), IDs ("2"), versions ("Github.v2"), ranges ("1-10").
	IncludeDetectors []string `json:"include_detectors"`

	// ExcludeDetectors removes detectors, applied after IncludeDetectors.
	ExcludeDetectors []string `json:"exclude_detectors"`

	// Verify enables live verification, which sends candidate secrets to
	// third-party APIs and adds their latency. Off by default.
	Verify bool `json:"verify"`

	// FilterEntropy drops unverified results below this Shannon entropy.
	// Zero disables the filter.
	FilterEntropy float64 `json:"filter_entropy"`

	// FilterUnverified keeps only the first unverified result per detector per
	// match (trufflehog's detectors.CleanResults behaviour).
	FilterUnverified bool `json:"filter_unverified"`

	// DropWordlistFPs discards unverified results that trufflehog's wordlist
	// check flags as false positives. Enabled unless explicitly disabled.
	DropWordlistFPs *bool `json:"drop_wordlist_fps"`

	// ScanEntireChunk passes the whole input to each matching detector instead
	// of a window around the matched keyword. Slower, but catches credentials
	// whose parts are far apart.
	ScanEntireChunk bool `json:"scan_entire_chunk"`

	// DetectorTimeoutMS bounds a single detector invocation. Defaults to 2000.
	DetectorTimeoutMS int `json:"detector_timeout_ms"`

	// Concurrency bounds parallel detector invocations. Defaults to NumCPU.
	Concurrency int `json:"concurrency"`

	// IncludeRaw includes the raw secret in findings. Tests only: echoing
	// secrets into logs or responses defeats the point of this package.
	IncludeRaw bool `json:"include_raw"`

	// MaxBytes truncates input before scanning. Defaults to 1 MiB.
	MaxBytes int `json:"max_bytes"`

	// SkipWarmup disables the one-time detector warm-up done by New. Leave it
	// on unless you are measuring startup cost.
	SkipWarmup bool `json:"skip_warmup"`
}

// ParseConfig decodes a JSON config, rejecting unknown fields so configuration
// typos surface as errors.
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

// catchAllID identifies our own catch-all detector. Version 0: there is one.
var catchAllID = thconfig.DetectorID{ID: detector_typepb.DetectorType_CustomRegex}

// parseDetectorIDs converts detector selectors into a set of DetectorIDs.
//
// catchAllSelector is resolved here rather than by trufflehog's parser, which
// only knows the names in its protobuf enum.
func parseDetectorIDs(selectors []string) (map[thconfig.DetectorID]struct{}, error) {
	out := make(map[thconfig.DetectorID]struct{})
	if len(selectors) == 0 {
		return out, nil
	}

	remaining := make([]string, 0, len(selectors))
	for _, s := range selectors {
		if strings.EqualFold(strings.TrimSpace(s), catchAllSelector) {
			out[catchAllID] = struct{}{}
			continue
		}
		remaining = append(remaining, s)
	}
	if len(remaining) == 0 {
		return out, nil
	}

	ids, err := thconfig.ParseDetectors(strings.Join(remaining, ","))
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out, nil
}

// inSet reports whether a detector is selected by a DetectorID set. As in
// trufflehog's engine, a set entry with Version 0 means every version of that
// type, so "Github" selects both github/v1 and github/v2.
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

// extraDetectors returns the detectors that defaults.DefaultDetectors does not
// contain, and which would otherwise be unreachable here.
//
//   - trufflehog's Generic: upstream ships it commented out of the default list,
//     so without this no selector could ever resolve to it. Included verbatim, so
//     that asking for Generic gets trufflehog's behaviour, warts and all.
//   - our own catch-all, selected as "HighEntropy": Generic without the base64
//     blind spot. See catchall.go.
//
// These are only ever selected by name, never by a group such as "all", so no
// profile picks up a catch-all by accident; see resolveDetectors.
func extraDetectors() []detectors.Detector {
	g := generic.New()
	return []detectors.Detector{&g, newCatchAllDetector()}
}

// namedSelectors drops trufflehog's special group names, leaving the selectors
// that name detectors directly.
//
// "all" expands to every DetectorID in the protobuf, including ones upstream
// ships disabled and our own CustomRegex slot, so it cannot be used to decide
// whether a detector was asked for deliberately.
func namedSelectors(selectors []string) []string {
	out := make([]string, 0, len(selectors))
	for _, s := range selectors {
		if strings.EqualFold(strings.TrimSpace(s), ProfileAll) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// allDetectors is the pool a selection is resolved against: everything
// trufflehog enables by default, plus extraDetectors.
//
// Deduplicated by DetectorID so that an upstream release re-enabling one of the
// extras adds nothing rather than counting it twice.
func allDetectors() []detectors.Detector {
	base := defaults.DefaultDetectors()
	extras := extraDetectors()
	out := make([]detectors.Detector, 0, len(base)+len(extras))
	seen := make(map[thconfig.DetectorID]struct{}, len(base))

	for _, d := range append(base, extras...) {
		id := thconfig.GetDetectorID(d)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, d)
	}
	return out
}

// resolveDetectors builds the effective list: profile, plus includes, minus excludes.
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

	// The extras must be asked for by name. Resolving them from `selected` would
	// let the "all" group enable a catch-all detector, which would make "all"
	// unusably noisy and take the choice away from the caller.
	explicit, err := parseDetectorIDs(append(
		namedSelectors(names), namedSelectors(cfg.IncludeDetectors)...))
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", cfg.Profile, err)
	}
	extras := make(map[thconfig.DetectorID]struct{})
	for _, d := range extraDetectors() {
		extras[thconfig.GetDetectorID(d)] = struct{}{}
	}

	all := allDetectors()
	out := make([]detectors.Detector, 0, len(all))
	for _, d := range all {
		wanted := selected
		if _, isExtra := extras[thconfig.GetDetectorID(d)]; isExtra {
			wanted = explicit
		}
		if !inSet(d, wanted) {
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
