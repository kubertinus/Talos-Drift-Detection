"""Let's Encrypt certificates via the lego ACME client.

HTTP-01: lego writes the challenge into a webroot that the plain-HTTP
listener serves at /.well-known/acme-challenge/ (port 80 on the host must
reach it). DNS-01: lego creates a TXT record through one of its DNS
providers, configured with environment variables.

lego's account and certificate directory is kept as an encrypted tarball in
the vault and only unpacked in tmpfs while lego runs.
"""
import asyncio
import io
import json
import logging
import os
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import config, tls, vault

log = logging.getLogger("acme")
SETTINGS, STATE, STATUS = "acme.settings", "acme.state", "acme.status"
LEGO = os.environ.get("LEGO", "lego")
WEBROOT = config.TMP_DIR / "acme-webroot"
ACME_SERVER = os.environ.get("ACME_SERVER", "")  # override, e.g. a test CA
RENEW_CHECK = 12 * 3600
_lock = asyncio.Lock()


def settings() -> dict:
    data = vault.get().load(SETTINGS)
    s = json.loads(data) if data else {}
    s.setdefault("domains", [])
    s.setdefault("email", "")
    s.setdefault("challenge", "http")
    s.setdefault("dns_provider", "")
    s.setdefault("dns_env", "")
    s.setdefault("dns_file", "")
    s.setdefault("staging", False)
    return s


def save_settings(s: dict) -> None:
    vault.get().save(SETTINGS, json.dumps(s).encode())


def status() -> dict:
    data = vault.get().load(STATUS)
    return json.loads(data) if data else {}


def _set_status(**kw) -> None:
    vault.get().save(STATUS, json.dumps({**status(), **kw}).encode())


def is_running() -> bool:
    return _lock.locked()


def validate(s: dict) -> str | None:
    if not s["domains"]:
        return "Enter at least one domain name."
    for d in s["domains"]:
        if not re.fullmatch(r"(\*\.)?([a-z0-9-]+\.)+[a-z]{2,63}", d):
            return f"{d} is not a valid (public) domain name."
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", s["email"]):
        return "Enter a valid email address."
    if s["challenge"] == "http" and any(d.startswith("*.") for d in s["domains"]):
        return "Wildcard certificates require the DNS challenge."
    if s["challenge"] == "dns" and not re.fullmatch(r"[a-z0-9]+", s["dns_provider"]):
        return "Choose a DNS provider (lego code, e.g. cloudflare or transip)."
    return None


def _env_lines(text: str) -> dict[str, str]:
    env = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def _restore_state(path: Path) -> None:
    data = vault.get().load(STATE)
    if data:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            tar.extractall(path, filter="data")


def _save_state(path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(path, arcname=".")
    vault.get().save(STATE, buf.getvalue())


def _find(path: Path, name: str, suffix: str) -> Path | None:
    hits = [p for p in path.rglob(f"{name}{suffix}") if p.is_file()]
    return max(hits, key=lambda p: p.stat().st_mtime) if hits else None


async def dns_help(provider: str) -> str:
    if not re.fullmatch(r"[a-z0-9]+", provider or ""):
        return ""
    proc = await asyncio.create_subprocess_exec(
        LEGO, "dnshelp", "--code", provider, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(config.TMP_DIR)},
    )
    out, _ = await proc.communicate()
    return out.decode(errors="replace").strip()


async def obtain(force: bool = False) -> tuple[bool, str]:
    """Get or renew the certificate and install it. Returns (success, log tail)."""
    async with _lock:
        s = settings()
        error = validate(s)
        if error:
            return False, error
        WEBROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=config.TMP_DIR) as tmp:
            tmp = Path(tmp)
            store = tmp / "lego"
            store.mkdir()
            _restore_state(store)
            server = ACME_SERVER or ("letsencrypt-staging" if s["staging"] else "letsencrypt")
            args = [
                "run", "--accept-tos", "--email", s["email"], "--domains", ",".join(s["domains"]),
                "--path", str(store), "--server", server, "--no-random-sleep", "--log.format", "text",
            ]
            env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp)}
            if os.environ.get("LEGO_CA_CERTIFICATES"):
                env["LEGO_CA_CERTIFICATES"] = os.environ["LEGO_CA_CERTIFICATES"]
            if s["challenge"] == "dns":
                args += ["--dns", s["dns_provider"]]
                file_path = tmp / "credential"
                if s["dns_file"]:
                    fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as f:
                        f.write(s["dns_file"])
                env |= {k: v.replace("{file}", str(file_path)) for k, v in _env_lines(s["dns_env"]).items()}
            else:
                args += ["--http", "--http.webroot", str(WEBROOT)]
            if force:
                args.append("--renew-force")
            proc = await asyncio.create_subprocess_exec(
                LEGO, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), 600)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                out = b"lego: timed out after 10 minutes"
            output = out.decode(errors="replace")
            tail = "\n".join(output.strip().splitlines()[-15:])
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            if proc.returncode != 0:
                log.warning("lego failed: %s", tail)
                _set_status(last_run=now, ok=False, message=tail)
                return False, tail
            _save_state(store)
            name = s["domains"][0].replace("*", "_")
            crt, key = _find(store, name, ".crt"), _find(store, name, ".key")
            if not crt or not key:
                _set_status(last_run=now, ok=False, message="lego returned no certificate")
                return False, "lego returned no certificate.\n" + tail
            try:
                fullchain, key_pem, chain = tls.prepare(crt.read_bytes(), key.read_bytes())
                current = tls.meta() or {}
                info = tls.describe(chain, "letsencrypt", staging=s["staging"], server=server)
                if current.get("fingerprint") != info["fingerprint"]:
                    tls.install(fullchain, key_pem, info)
            except tls.CertError as e:
                _set_status(last_run=now, ok=False, message=str(e))
                return False, str(e)
            _set_status(last_run=now, ok=True, message=tail)
            return True, tail


async def renew_loop() -> None:
    """Renew the Let's Encrypt certificate when lego says it is due."""
    while True:
        await asyncio.sleep(RENEW_CHECK)
        try:
            if (tls.meta() or {}).get("source") == "letsencrypt":
                ok, msg = await obtain()
                log.info("renewal check: %s", "ok" if ok else msg)
        except Exception:
            log.exception("renewal check failed")
