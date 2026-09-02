# Builds a manylinux wheel containing the compiled Go shared library, tagged
# py3-none-manylinux_2_28_x86_64: platform-specific, but ABI-independent because
# the library is loaded with ctypes rather than linked against libpython.
#
#   docker build -f docker/build-wheel.Dockerfile -o dist .
#
# `-o dist` uses BuildKit's local exporter to write the wheel straight to ./dist.

ARG MANYLINUX_IMAGE=quay.io/pypa/manylinux_2_28_x86_64
ARG GO_VERSION=1.25.5
ARG PYTHON_BIN=/opt/python/cp311-cp311/bin/python

FROM ${MANYLINUX_IMAGE} AS builder
ARG GO_VERSION
ARG PYTHON_BIN

# manylinux_2_28 is AlmaLinux 8 (glibc 2.28), which covers current Debian, Ubuntu
# and the official LiteLLM images.
RUN curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
      | tar -C /usr/local -xz \
 && /usr/local/go/bin/go version
ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=auto \
    CGO_ENABLED=1

WORKDIR /src

# Warm the module cache first so source edits do not re-download ~400 modules.
COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download

COPY . .

RUN ${PYTHON_BIN} -m pip install --no-cache-dir -q build auditwheel \
 && ${PYTHON_BIN} -m build --wheel --outdir /dist

# Confirm the library only needs manylinux-approved shared objects; a failure
# here means the wheel is silently non-portable.
RUN auditwheel show /dist/*.whl

# Smoke-test on a *different* Python version than it was built with, to prove the
# single wheel really is ABI-independent.
RUN /opt/python/cp312-cp312/bin/python -m pip install --no-cache-dir -q /dist/*.whl \
 && /opt/python/cp312-cp312/bin/python -c "\
import litellm_trufflehog as t; \
s = t.Scanner(profile='core'); \
print('trufflehog', t.native_version()['trufflehog'], 'detectors', s.detector_count); \
assert s.warmup_errors == [], s.warmup_errors; \
r = s.scan('token ghp_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5'); \
assert 'Github' in {f.detector_type for f in r.findings}, r; \
assert not s.scan('hello world').findings; \
print('wheel smoke test OK')"

FROM scratch AS export
COPY --from=builder /dist/ /
