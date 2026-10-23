# Minimal, CVE-free image: Chainguard (Wolfi) Python without shell or package manager,
# with talosctl and lego compiled from source using the newest Go toolchain.

# "latest" resolves to the newest stable release at build time; set a tag (e.g. v1.11.5) to pin.
ARG TALOSCTL_VERSION=latest
ARG LEGO_VERSION=latest

# --- talosctl + lego ---------------------------------------------------------
# Built from source instead of using the release binaries, so they pick up the
# newest Go standard library and golang.org/x fixes. Runs on the build platform
# and cross-compiles, so no emulation is needed for the other architecture.
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS gobuild
ARG TALOSCTL_VERSION
ARG LEGO_VERSION
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOOS=$TARGETOS GOARCH=$TARGETARCH

# Docker re-fetches these URLs on every build and only invalidates the cache below
# when their content changes, i.e. when a new release is published.
ADD https://api.github.com/repos/siderolabs/talos/releases/latest /tmp/talos-latest.json
ADD https://api.github.com/repos/go-acme/lego/releases/latest /tmp/lego-latest.json

WORKDIR /src
RUN set -eu; \
    resolve() { [ "$1" = latest ] && sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$2" | head -1 || echo "$1"; }; \
    talos="$(resolve "$TALOSCTL_VERSION" /tmp/talos-latest.json)"; \
    lego="$(resolve "$LEGO_VERSION" /tmp/lego-latest.json)"; \
    echo "Building talosctl ${talos} and lego ${lego} for ${GOOS}/${GOARCH} with $(go version)"; \
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$talos" https://github.com/siderolabs/talos.git talos; \
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$lego" https://github.com/go-acme/lego.git lego; \
    cd /src/talos; \
    printf %s "$talos" > pkg/machinery/gendata/data/tag; \
    printf %s "$(git rev-parse --short HEAD)" > pkg/machinery/gendata/data/sha; \
    go get golang.org/x/crypto@latest golang.org/x/net@latest; \
    go mod tidy; \
    go build -trimpath -tags grpcnotrace -ldflags "-s -w" -o /out/talosctl ./cmd/talosctl; \
    cd /src/lego; \
    go get golang.org/x/crypto@latest golang.org/x/net@latest; \
    go mod tidy; \
    go build -trimpath -ldflags "-s -w -X main.version=${lego#v}" -o /out/lego .; \
    mkdir -p /out/data

# --- Python dependencies ---------------------------------------------------------
FROM cgr.dev/chainguard/python:latest-dev AS pydeps
WORKDIR /srv
# A venv without pip/setuptools: they are only needed to install, not at runtime.
RUN python -m venv --without-pip /srv/venv
COPY requirements.txt .
RUN pip --python /srv/venv/bin/python install --no-cache-dir -r requirements.txt

# --- runtime ---------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest
WORKDIR /srv
COPY --from=pydeps /srv/venv /srv/venv
COPY --from=gobuild /out/talosctl /out/lego /usr/local/bin/
COPY app ./app
# Same uid as earlier images, so existing /data volumes stay readable.
COPY --from=gobuild --chown=10001:10001 /out/data /data
USER 10001

ENV PATH=/srv/venv/bin:/usr/local/bin:/usr/bin \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data TMP_DIR=/tmp
# 8443: the app over HTTPS. 8080: plain HTTP, only redirects to HTTPS and serves ACME challenges.
EXPOSE 8443 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD ["/srv/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]
ENTRYPOINT ["/srv/venv/bin/python", "-m", "app.server"]
