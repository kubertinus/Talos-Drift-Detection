FROM python:3.12-slim

# "latest" resolves to the newest stable release at build time; set a tag (e.g. v1.11.5) to pin.
ARG TALOSCTL_VERSION=latest
ARG LEGO_VERSION=latest
ARG TARGETARCH

# Docker re-fetches these URLs on every build and only invalidates the cache below
# when their content changes, i.e. when a new release is published.
ADD https://api.github.com/repos/siderolabs/talos/releases/latest /tmp/talos-latest.json
ADD https://api.github.com/repos/go-acme/lego/releases/latest /tmp/lego-latest.json

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && version="${TALOSCTL_VERSION}" \
 && if [ "$version" = "latest" ]; then \
      version="$(python -c 'import json; print(json.load(open("/tmp/talos-latest.json"))["tag_name"])')"; \
    fi \
 && echo "Installing talosctl ${version} (${TARGETARCH})" \
 && base="https://github.com/siderolabs/talos/releases/download/${version}" \
 && curl -fsSLo /usr/local/bin/talosctl-linux-${TARGETARCH} "${base}/talosctl-linux-${TARGETARCH}" \
 && curl -fsSLo /tmp/sha256sum.txt "${base}/sha256sum.txt" \
 && cd /usr/local/bin \
 && grep " talosctl-linux-${TARGETARCH}\$" /tmp/sha256sum.txt | sha256sum -c - \
 && mv talosctl-linux-${TARGETARCH} talosctl && chmod 0755 talosctl \
 && rm /tmp/sha256sum.txt /tmp/talos-latest.json \
 && version="${LEGO_VERSION}" \
 && if [ "$version" = "latest" ]; then \
      version="$(python -c 'import json; print(json.load(open("/tmp/lego-latest.json"))["tag_name"])')"; \
    fi \
 && echo "Installing lego ${version} (${TARGETARCH})" \
 && base="https://github.com/go-acme/lego/releases/download/${version}" \
 && asset="lego_${version}_linux_${TARGETARCH}.tar.gz" \
 && cd /tmp \
 && curl -fsSLo "${asset}" "${base}/${asset}" \
 && curl -fsSLo lego-checksums.txt "${base}/lego_${version#v}_checksums.txt" \
 && grep " ${asset}\$" lego-checksums.txt | sha256sum -c - \
 && tar -xzf "${asset}" -C /usr/local/bin lego && chmod 0755 /usr/local/bin/lego \
 && rm "${asset}" lego-checksums.txt /tmp/lego-latest.json \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd --system --uid 10001 --home-dir /nonexistent app \
 && mkdir -p /data && chown app /data
USER 10001

ENV PYTHONUNBUFFERED=1 DATA_DIR=/data TMP_DIR=/tmp
# 8443: the app over HTTPS. 8080: plain HTTP, only redirects to HTTPS and serves ACME challenges.
EXPOSE 8443 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["python", "-m", "app.server"]
