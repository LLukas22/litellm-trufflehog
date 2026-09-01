# Development and release tasks for litellm-trufflehog.
#
#   just dev      build the shared library, sync the venv, run every check
#   just wheel    build the release manylinux wheel in Docker
#
# The release artifact must be built in the manylinux container: a library
# compiled against a host glibc is not portable to other distributions.
#
# Recipes avoid shell chaining (`&&`, `cd x && y`) so they work under both sh and
# PowerShell; use the working-directory attribute instead.

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

go_version := "1.25.5"
manylinux_image := "quay.io/pypa/manylinux_2_28_x86_64"
native_dir := "src/litellm_trufflehog/_native"

lib_name := if os() == "windows" { "libthscan.dll" } else if os() == "macos" { "libthscan.dylib" } else { "libthscan.so" }

export GOTOOLCHAIN := "auto"
export CGO_ENABLED := "1"

# List available recipes
default:
    @just --list

# Create/refresh the virtualenv from pyproject + uv.lock
sync:
    uv sync --all-groups

# Update the lockfile
lock:
    uv lock

[doc("Build the Go shared library into the package directory (needed for tests)")]
[working-directory: 'go']
build:
    go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o ../{{native_dir}}/{{lib_name}} ./cbind

[doc("Run the Go test suite")]
[working-directory: 'go']
test-go:
    go test ./... -count=1

[doc("Run the Go test suite under the race detector")]
[working-directory: 'go']
test-race:
    go test ./... -count=1 -race

[doc("Run go vet")]
[working-directory: 'go']
vet:
    go vet ./...

[doc("Run Go benchmarks (the scanner in isolation)")]
[working-directory: 'go']
bench-go:
    go test ./scanner/ -run XXX -bench . -benchmem

[doc("Run Python benchmarks (the full call path, as a caller pays it)")]
bench-py *ARGS:
    uv run pytest --benchmark-only --benchmark-columns=min,mean,median,stddev,ops,rounds --benchmark-group-by=group --benchmark-sort=mean {{ARGS}}

# Run both benchmark suites
bench: bench-go bench-py

[doc("Save a Python benchmark baseline for later --benchmark-compare runs")]
bench-save NAME="baseline":
    uv run pytest --benchmark-only --benchmark-save={{NAME}} --benchmark-group-by=group

[doc("Compare Python benchmarks against a saved baseline")]
bench-compare NAME="0001":
    uv run pytest --benchmark-only --benchmark-compare={{NAME}} --benchmark-group-by=group

[doc("Format Go sources")]
[working-directory: 'go']
fmt-go:
    go fmt ./...

# Run the Python test suite (requires `just build`)
test-py:
    uv run pytest

# Run all tests
test: test-go test-py

# Type-check with ty
typecheck:
    uv run ty check

# Lint and format-check with ruff
lint:
    uv run ruff check .
    uv run ruff format --check .

# Apply ruff autofixes and formatting, and gofmt
fmt: fmt-go
    uv run ruff check --fix .
    uv run ruff format .

# Everything CI runs
check: vet lint typecheck test

# Build the shared library, sync the venv, then run every check
dev: build sync check

# Build the release manylinux wheel into ./dist
wheel:
    docker build -f docker/build-wheel.Dockerfile --build-arg GO_VERSION={{go_version}} --build-arg MANYLINUX_IMAGE={{manylinux_image}} -o dist .

[doc("Remove build artifacts")]
[unix]
clean:
    rm -rf build dist .pytest_cache .ruff_cache src/*.egg-info
    rm -f {{native_dir}}/libthscan.*
    find . -name __pycache__ -type d -prune -exec rm -rf {} +

[doc("Remove build artifacts")]
[windows]
clean:
    -Remove-Item -Recurse -Force build,dist,.pytest_cache,.ruff_cache -ErrorAction SilentlyContinue
    -Remove-Item -Force "{{native_dir}}/libthscan.*" -ErrorAction SilentlyContinue
    -Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
