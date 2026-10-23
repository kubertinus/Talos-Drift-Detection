# Minimal, CVE-free image: Chainguard (Wolfi) Python without shell or package manager,
# with talosctl and lego compiled from source using the newest Go toolchain.
#
# The build stages use Debian-based images (golang, python): on the CI runner, network
# traffic from RUN steps in Wolfi images is refused inside BuildKit (sendto: EACCES), while
# Debian-based steps work. Only the runtime image is Chainguard, which is what ships.

# "latest" resolves to the newest stable release at build time; set a tag (e.g. v1.11.5) to pin.
ARG TALOSCTL_VERSION=latest
ARG LEGO_VERSION=latest
# Python minor version for installing the dependencies; must match the runtime image.
ARG PYTHON_VERSION=3.15

# --- talosctl + lego ---------------------------------------------------------
# Built from source instead of using the release binaries, so they pick up the
# newest Go standard library and golang.org/x fixes. Runs on the build platform
# and cross-compiles, so no emulation is needed for the other architecture.
FROM --platform=$BUILDPLATFORM golang:latest AS gobuild
ARG TALOSCTL_VERSION
ARG LEGO_VERSION
ARG TARGETOS
ARG TARGETARCH
# GOWORK=off: the talos module ships a go.work listing tool modules that are not part of it.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOOS=$TARGETOS GOARCH=$TARGETARCH

# Cache buster: Docker re-fetches these feeds on every build and only invalidates the
# layers below when they change, i.e. when a release is published. (The GitHub API is
# avoided: unauthenticated it allows 60 requests per hour, too few for shared CI runners.)
ADD https://github.com/siderolabs/talos/releases.atom /tmp/talos-releases.atom
ADD https://github.com/go-acme/lego/releases.atom /tmp/lego-releases.atom

# Resolve "latest" to the newest stable vX.Y.Z release from the feeds above; fails loudly
# instead of building nothing.
WORKDIR /src
RUN set -eu; \
    resolve() { \
      if [ "$2" != latest ]; then echo "$2"; return; fi; \
      grep -o '<id>tag:github.com,2008:Repository/[0-9]*/v[0-9]*\.[0-9]*\.[0-9]*</id>' "$1" \
        | sed 's|.*/\(v[^<]*\)</id>|\1|' | sort -V | tail -1; \
    }; \
    talos="$(resolve /tmp/talos-releases.atom "$TALOSCTL_VERSION")"; \
    lego="$(resolve /tmp/lego-releases.atom "$LEGO_VERSION")"; \
    [ -n "$talos" ] && [ -n "$lego" ] || { echo "Could not resolve versions (talos='$talos' lego='$lego')" >&2; exit 1; }; \
    printf 'TALOS=%s\nLEGO=%s\n' "$talos" "$lego" > /src/versions; \
    echo "Building talosctl ${talos} and lego ${lego} for ${GOOS}/${GOARCH} with $(go version)"

# Sources come from the Go module proxy (checksum-verified against sum.golang.org).
# talos replaces its nested pkg/machinery module with ./pkg/machinery, so that module is
# fetched separately and put in place.
RUN set -eu; . /src/versions; \
    fetch() { \
      dir="$(go mod download -json "$1@$2" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"; \
      [ -n "$dir" ] || { echo "go mod download $1@$2 failed" >&2; exit 1; }; \
      rm -rf "$3"; cp -R "$dir" "$3"; chmod -R u+w "$3"; \
    }; \
    lego_major="${LEGO%%.*}"; lego_mod=github.com/go-acme/lego; \
    [ "$lego_major" = v0 ] || [ "$lego_major" = v1 ] || lego_mod="$lego_mod/$lego_major"; \
    fetch github.com/siderolabs/talos "$TALOS" talos; \
    fetch github.com/siderolabs/talos/pkg/machinery "$TALOS" talos/pkg/machinery; \
    fetch "$lego_mod" "$LEGO" lego; \
    go clean -modcache

RUN set -eu; . /src/versions; cd /src/talos; \
    printf %s "$TALOS" > pkg/machinery/gendata/data/tag; \
    printf %s undefined > pkg/machinery/gendata/data/sha; \
    go get golang.org/x/crypto@latest golang.org/x/net@latest; \
    go mod tidy; \
    go build -trimpath -tags grpcnotrace -ldflags "-s -w" -o /out/talosctl ./cmd/talosctl; \
    go clean -cache

RUN set -eu; . /src/versions; cd /src/lego; \
    go get golang.org/x/crypto@latest golang.org/x/net@latest; \
    go mod tidy; \
    go build -trimpath -ldflags "-s -w -X main.version=${LEGO#v}" -o /out/lego .; \
    go clean -cache; \
    mkdir -p /out/data

# --- Python dependencies ---------------------------------------------------------
# Installed into a plain directory (no pip/setuptools at runtime). Must be the same Python
# minor version as the runtime image; the pycheck stage below enforces that.
FROM python:${PYTHON_VERSION}-slim AS pydeps
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore --target /srv/site-packages -r requirements.txt \
 && python -c "import sys; print('%d.%d' % sys.version_info[:2])" > /srv/python-version

# Fails the build if the runtime Python (Chainguard "latest") moved to another minor
# version than the one the dependencies were installed for. Needs no network.
FROM cgr.dev/chainguard/python:latest-dev AS pycheck
COPY --from=pydeps /srv/python-version /tmp/python-version
RUN python -c "import sys; want = open('/tmp/python-version').read().strip(); have = '%d.%d' % sys.version_info[:2]; sys.exit(0 if want == have else f'Runtime Python {have} != dependency Python {want}: set PYTHON_VERSION={have}')" \
 && touch /tmp/python-ok

# --- runtime ---------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest
WORKDIR /srv
COPY --from=pydeps /srv/site-packages /srv/site-packages
COPY --from=pycheck /tmp/python-ok /srv/.python-ok
COPY --from=gobuild /out/talosctl /out/lego /usr/local/bin/
COPY app ./app
# Same uid as earlier images, so existing /data volumes stay readable.
COPY --from=gobuild --chown=10001:10001 /out/data /data
USER 10001

ENV PATH=/usr/local/bin:/usr/bin PYTHONPATH=/srv/site-packages \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data TMP_DIR=/tmp
# 8443: the app over HTTPS. 8080: plain HTTP, only redirects to HTTPS and serves ACME challenges.
EXPOSE 8443 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]
ENTRYPOINT ["/usr/bin/python", "-m", "app.server"]
