// Command cbind exposes the scanner package as a C shared library.
//
// Build with:
//
//	go build -buildmode=c-shared -o libthscan.so ./cbind
//
// The resulting library is loaded from Python with ctypes. That choice is
// deliberate: a c-shared library has no CPython ABI dependency, so a single
// artifact serves every CPython 3.x, and ctypes releases the GIL around the
// foreign call, so concurrent scans genuinely run in parallel.
//
// Conventions:
//   - Scanners live in a registry and are addressed by an opaque int64 handle.
//     No Go pointer ever crosses the boundary, which cgo forbids anyway.
//   - Functions returning char* return a C-allocated string that the caller
//     must release with th_free. A NULL return means failure; call
//     th_last_error for the message.
//   - Input buffers are copied into Go memory immediately; the library never
//     retains a caller pointer.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/LLukas22/litellm-trufflehog/go/scanner"
)

func init() { sanitizeStdio() }

// keepStdioEnv re-enables Go-side stdout/stderr, for debugging only.
const keepStdioEnv = "LITELLM_TRUFFLEHOG_KEEP_STDIO"

// stdioFileEnv names a file to receive Go-side stdout/stderr instead of the null
// device. The only way to see a native panic when the host has taken over the
// standard handles: a panic aborts the process, so anything buffered in the
// host's capture machinery is lost with it.
const stdioFileEnv = "LITELLM_TRUFFLEHOG_STDIO_FILE"

// sanitizeStdio redirects Go's os.Stdout/os.Stderr to the null device.
//
// Two reasons, both about being a library rather than a program:
//
// 1. Correctness for the host. We are loaded into someone else's process. Any
// dependency that writes to stdout would interleave with - and could corrupt -
// the host's own output.
//
// 2. Robustness. Code in this dependency tree passes os.Stdout around without
// checking that it still works. github.com/wasilibs/go-re2, which trufflehog
// uses for detector regexes, instantiates its wazero WASM module with
// `WithStdout(os.Stdout)` (re2_wazero.go:107) on the child-module path, while
// only its root-module path guards with a Stat check. When the host has left
// the standard handles unusable - a daemonised proxy that closed them, or
// pytest's output capture on Windows - that unguarded path fails with
// "GetFileType /dev/stdout: The handle is invalid" and panics inside whichever
// detector happened to run first.
//
// That panic is worse than it looks: it aborts one detector, so the scan can
// return no findings and be mistaken for "no secrets present". Pointing stdio
// at the null device makes those handles unconditionally valid and removes the
// failure mode at its source, rather than hoping every dependency checks.
func sanitizeStdio() {
	if os.Getenv(keepStdioEnv) != "" {
		return
	}
	if path := os.Getenv(stdioFileEnv); path != "" {
		if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
			os.Stdout = f
			os.Stderr = f
			fmt.Fprintf(f, "[sanitizeStdio] redirected to %s\n", path)
			return
		}
	}
	if f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stdout = f
	}
	if f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stderr = f
	}
}

// Handle error sentinels returned by th_new.
const (
	errInvalidArgument = -1
	errConfig          = -2
	errPanic           = -3
)

var (
	registryMu sync.RWMutex
	registry   = make(map[int64]*scanner.Scanner)
	nextHandle atomic.Int64

	lastErrMu sync.Mutex
	lastErr   string
)

func setLastError(err error) {
	lastErrMu.Lock()
	defer lastErrMu.Unlock()
	if err == nil {
		lastErr = ""
		return
	}
	lastErr = err.Error()
}

func lookup(handle int64) (*scanner.Scanner, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := registry[handle]
	return s, ok
}

// cString copies s into C-allocated memory. The caller frees it with th_free.
func cString(s string) *C.char { return C.CString(s) }

//export th_version
func th_version() *C.char {
	info := map[string]string{
		"scanner":    "0.1.0",
		"trufflehog": "unknown",
		"go":         "unknown",
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info["go"] = bi.GoVersion
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/trufflesecurity/trufflehog/v3" {
				info["trufflehog"] = dep.Version
				break
			}
		}
	}
	out, err := json.Marshal(info)
	if err != nil {
		setLastError(err)
		return nil
	}
	return cString(string(out))
}

//export th_profiles
func th_profiles() *C.char {
	out, err := json.Marshal(scanner.Profiles())
	if err != nil {
		setLastError(err)
		return nil
	}
	return cString(string(out))
}

//export th_last_error
func th_last_error() *C.char {
	lastErrMu.Lock()
	defer lastErrMu.Unlock()
	return cString(lastErr)
}

// th_new builds a scanner from a JSON config and returns a positive handle, or
// a negative error sentinel. Building the Aho-Corasick trie over the selected
// detectors happens here, so this call is the expensive one.
//
//export th_new
func th_new(cfgJSON *C.char) C.longlong {
	defer func() {
		if r := recover(); r != nil {
			setLastError(fmt.Errorf("panic while creating scanner: %v", r))
		}
	}()
	setLastError(nil)

	var raw []byte
	if cfgJSON != nil {
		raw = []byte(C.GoString(cfgJSON))
	}

	cfg, err := scanner.ParseConfig(raw)
	if err != nil {
		setLastError(err)
		return errConfig
	}

	s, err := scanner.New(cfg)
	if err != nil {
		setLastError(err)
		return errConfig
	}

	handle := nextHandle.Add(1)
	registryMu.Lock()
	registry[handle] = s
	registryMu.Unlock()

	return C.longlong(handle)
}

//export th_close
func th_close(handle C.longlong) C.int {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, ok := registry[int64(handle)]; !ok {
		return 0
	}
	delete(registry, int64(handle))
	return 1
}

//export th_detector_count
func th_detector_count(handle C.longlong) C.longlong {
	s, ok := lookup(int64(handle))
	if !ok {
		setLastError(fmt.Errorf("unknown scanner handle %d", int64(handle)))
		return errInvalidArgument
	}
	return C.longlong(s.DetectorCount())
}

// th_warmup_errors returns a JSON array of detectors that failed their one-time
// initialisation. A non-empty array means reduced coverage.
//
//export th_warmup_errors
func th_warmup_errors(handle C.longlong) *C.char {
	s, ok := lookup(int64(handle))
	if !ok {
		setLastError(fmt.Errorf("unknown scanner handle %d", int64(handle)))
		return nil
	}
	out, err := json.Marshal(s.WarmupErrors())
	if err != nil {
		setLastError(err)
		return nil
	}
	return cString(string(out))
}

// th_scan scans n bytes at buf and returns the report as a JSON string, or NULL
// on failure.
//
//export th_scan
func th_scan(handle C.longlong, buf *C.char, n C.int) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			setLastError(fmt.Errorf("panic during scan: %v", r))
			result = nil
		}
	}()
	setLastError(nil)

	s, ok := lookup(int64(handle))
	if !ok {
		setLastError(fmt.Errorf("unknown scanner handle %d", int64(handle)))
		return nil
	}
	if n < 0 {
		setLastError(fmt.Errorf("negative length %d", int(n)))
		return nil
	}

	// Copy into Go memory: the caller's buffer must not be retained, and Python
	// may free or mutate it as soon as we return.
	var data []byte
	if n > 0 {
		if buf == nil {
			setLastError(fmt.Errorf("null buffer with length %d", int(n)))
			return nil
		}
		data = C.GoBytes(unsafe.Pointer(buf), n)
	}

	report := s.Scan(context.Background(), data)

	out, err := json.Marshal(report)
	if err != nil {
		setLastError(err)
		return nil
	}
	return cString(string(out))
}

//export th_free
func th_free(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

func main() {}
