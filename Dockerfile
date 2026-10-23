# Minimal image: Chainguard (Wolfi) Python without shell or package manager, plus the
# official talosctl and lego release binaries.
#
# Every RUN step runs on the build platform in a Debian-based image: no emulation is needed
# for the other architecture, and on the CI runner network traffic from RUN steps in Wolfi
# images is refused inside BuildKit. Only the runtime image is Chainguard.

# "latest" resolves to the newest stable release at build time; set a tag (e.g. v1.11.5) to pin.
ARG TALOSCTL_VERSION=latest
ARG LEGO_VERSION=latest
# Python minor version for installing the dependencies; must match the runtime image.
ARG PYTHON_VERSION=3.15

# --- talosctl + lego -------------------------------------------------------------
FROM --platform=$BUILDPLATFORM python:${PYTHON_VERSION}-slim AS binaries
ARG TALOSCTL_VERSION
ARG LEGO_VERSION
ARG TARGETARCH

# Cache buster: Docker re-fetches these feeds on every build and only invalidates the
# layers below when they change, i.e. when a release is published. (The GitHub API is
# avoided: unauthenticated it allows 60 requests per hour, too few for shared CI runners.)
ADD https://github.com/siderolabs/talos/releases.atom /tmp/talos-releases.atom
ADD https://github.com/go-acme/lego/releases.atom /tmp/lego-releases.atom

# Downloads the release binaries for the target architecture and verifies them against
# the release's checksum file.
RUN <<'EOF' python
import hashlib, io, os, re, tarfile, urllib.request

arch = os.environ["TARGETARCH"]

def latest(feed, wanted):
    if wanted != "latest":
        return wanted
    tags = re.findall(r"<id>tag:github.com,2008:Repository/\d+/(v\d+\.\d+\.\d+)</id>", open(feed).read())
    if not tags:
        raise SystemExit(f"no stable release found in {feed}")
    return max(tags, key=lambda t: tuple(map(int, t[1:].split("."))))

def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()

def verified(base, asset, sums_file):
    data = fetch(f"{base}/{asset}")
    sums = dict(reversed(line.split()) for line in fetch(f"{base}/{sums_file}").decode().splitlines() if line.strip())
    if hashlib.sha256(data).hexdigest() != sums.get(asset):
        raise SystemExit(f"checksum mismatch for {asset}")
    return data

def install(name, data):
    os.makedirs("/out", exist_ok=True)
    with open(f"/out/{name}", "wb") as f:
        f.write(data)
    os.chmod(f"/out/{name}", 0o755)

talos = latest("/tmp/talos-releases.atom", os.environ["TALOSCTL_VERSION"])
lego = latest("/tmp/lego-releases.atom", os.environ["LEGO_VERSION"])
print(f"talosctl {talos} and lego {lego} for linux/{arch}")

install("talosctl", verified(f"https://github.com/siderolabs/talos/releases/download/{talos}",
                             f"talosctl-linux-{arch}", "sha256sum.txt"))
asset = f"lego_{lego}_linux_{arch}.tar.gz"
tgz = verified(f"https://github.com/go-acme/lego/releases/download/{lego}", asset, f"lego_{lego[1:]}_checksums.txt")
with tarfile.open(fileobj=io.BytesIO(tgz)) as tar:
    install("lego", tar.extractfile("lego").read())
os.makedirs("/out/data", exist_ok=True)
EOF

# --- Python dependencies ---------------------------------------------------------
# Wheels for the target platform are downloaded on the build platform (no emulation) into a
# plain directory, so there is no pip/setuptools at runtime. PyYAML has no wheel for every
# Python version; its pure-Python build works on any platform.
FROM --platform=$BUILDPLATFORM python:${PYTHON_VERSION}-slim AS pydeps
ARG TARGETARCH
WORKDIR /srv
COPY requirements.txt .
RUN set -eu; \
    case "$TARGETARCH" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; *) echo "unsupported $TARGETARCH" >&2; exit 1 ;; esac; \
    pyver="$(python -c "import sys; print('%d.%d' % sys.version_info[:2])")"; \
    grep -iv '^pyyaml' requirements.txt > /tmp/requirements.txt; \
    pip install --no-cache-dir --root-user-action=ignore --target /srv/site-packages \
        --platform "manylinux2014_$arch" --platform "manylinux_2_28_$arch" \
        --python-version "$pyver" --implementation cp --only-binary=:all: -r /tmp/requirements.txt; \
    pip wheel --no-cache-dir --no-deps --no-binary pyyaml -w /tmp/wheels "$(grep -i '^pyyaml' requirements.txt)"; \
    python -m zipfile -e /tmp/wheels/*.whl /srv/site-packages; \
    echo "$pyver" > /srv/python-version

# Fails the build if the runtime Python (Chainguard "latest") moved to another minor
# version than the one the dependencies were installed for. Needs no network.
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/python:latest-dev AS pycheck
COPY --from=pydeps /srv/python-version /tmp/python-version
RUN python -c "import sys; want = open('/tmp/python-version').read().strip(); have = '%d.%d' % sys.version_info[:2]; sys.exit(0 if want == have else f'Runtime Python {have} != dependency Python {want}: set PYTHON_VERSION={have}')" \
 && touch /tmp/python-ok

# --- runtime ---------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest
WORKDIR /srv
COPY --from=pydeps /srv/site-packages /srv/site-packages
COPY --from=pycheck /tmp/python-ok /srv/.python-ok
COPY --from=binaries /out/talosctl /out/lego /usr/local/bin/
COPY app ./app
# Same uid as earlier images, so existing /data volumes stay readable.
COPY --from=binaries --chown=10001:10001 /out/data /data
USER 10001:10001

ENV PATH=/usr/local/bin:/usr/bin PYTHONPATH=/srv/site-packages \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data TMP_DIR=/tmp
# 8443: the app over HTTPS. 8080: plain HTTP, only redirects to HTTPS and serves ACME challenges.
EXPOSE 8443 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"]
ENTRYPOINT ["/usr/bin/python", "-m", "app.server"]
