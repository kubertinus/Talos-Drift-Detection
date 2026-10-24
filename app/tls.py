"""HTTPS certificate management.

The active certificate (leaf + intermediates) and its key are stored encrypted
in the vault as `tls.cert` / `tls.key`, with metadata in `tls.meta`. The HTTPS
server gets one base SSLContext whose SNI callback hands every new connection
the context of the current certificate; installing a certificate builds a
fresh context, so it applies without a restart. (Loading a new certificate
into an existing context is not enough: OpenSSL keeps one certificate per key
type, so an RSA certificate would sit next to the old EC one, not replace it.)

Sources: a self-signed certificate (generated on first start), an uploaded
certificate with chain, or Let's Encrypt (see `acme.py`).
"""
import datetime as dt
import ipaddress
import json
import logging
import os
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import config, vault

log = logging.getLogger("tls")
CERT, KEY, META = "tls.cert", "tls.key", "tls.meta"

_active: ssl.SSLContext | None = None  # context of the current certificate
_active_source: str | None = None


class CertError(Exception):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --- parsing & validation --------------------------------------------------


def _load_certs(pem: bytes) -> list[x509.Certificate]:
    try:
        certs = x509.load_pem_x509_certificates(pem)
    except ValueError as e:
        raise CertError("No valid PEM certificate found.") from e
    return certs


def _load_key(pem: bytes, passphrase: str | None):
    try:
        return serialization.load_pem_private_key(pem, password=passphrase.encode() if passphrase else None)
    except TypeError as e:
        raise CertError("The private key is encrypted: enter the passphrase.") from e
    except ValueError as e:
        raise CertError("Not a valid private key, or wrong passphrase.") from e


def _public_bytes(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _is_self_signed(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def _order_chain(leaf: x509.Certificate, others: list[x509.Certificate]) -> list[x509.Certificate]:
    """Leaf first, then each issuer; unrelated certificates are dropped."""
    chain, current, pool = [leaf], leaf, list(others)
    while not _is_self_signed(current):
        issuer = next((c for c in pool if c.subject == current.issuer), None)
        if not issuer:
            break
        chain.append(issuer)
        pool.remove(issuer)
        current = issuer
    return chain


def _verify_signatures(chain: list[x509.Certificate]) -> None:
    for child, parent in zip(chain, chain[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except (InvalidSignature, ValueError, TypeError) as e:
            raise CertError(f"{_cn(child)} is not signed by {_cn(parent)}.") from e


def _cn(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    try:  # modern leaf certificates may only carry SANs
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
        if names:
            return names[0]
    except x509.ExtensionNotFound:
        pass
    return cert.subject.rfc4514_string() or "(no name)"


def _names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [_cn(cert)]
    return [str(n) for n in san.get_values_for_type(x509.DNSName)] + [
        str(ip) for ip in san.get_values_for_type(x509.IPAddress)
    ]


def describe(chain: list[x509.Certificate], source: str, **extra) -> dict:
    leaf = chain[0]
    return {
        "source": source,
        "subject": _cn(leaf),
        "names": _names(leaf),
        "issuer": _cn(chain[1]) if len(chain) > 1 else leaf.issuer.rfc4514_string(),
        "chain": [_cn(c) for c in chain],
        "not_before": leaf.not_valid_before_utc.isoformat(timespec="seconds"),
        "not_after": leaf.not_valid_after_utc.isoformat(timespec="seconds"),
        "fingerprint": leaf.fingerprint(hashes.SHA256()).hex(":")[:47],
        "installed": _now().isoformat(timespec="seconds"),
        **extra,
    }


def prepare(cert_pem: bytes, key_pem: bytes, chain_pem: bytes = b"", passphrase: str | None = None):
    """Validate an uploaded certificate; returns (fullchain PEM, key PEM, chain).

    The served chain is leaf + intermediates; a self-signed root is checked
    but not sent (clients have it in their trust store).
    """
    certs = _load_certs(cert_pem + b"\n" + chain_pem)
    key = _load_key(key_pem, passphrase)
    leaf = next((c for c in certs if _public_bytes(c.public_key()) == _public_bytes(key.public_key())), None)
    if leaf is None:
        raise CertError("The private key does not match any of the certificates.")
    if leaf.not_valid_after_utc < _now():
        raise CertError(f"The certificate expired on {leaf.not_valid_after_utc:%Y-%m-%d}.")
    chain = _order_chain(leaf, [c for c in certs if c is not leaf])
    _verify_signatures(chain)
    served = [c for c in chain if not (_is_self_signed(c) and c is not leaf)]
    fullchain = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in served)
    key_out = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return fullchain, key_out, chain


# --- self-signed -------------------------------------------------------------


def default_names() -> list[str]:
    names = ["localhost", "127.0.0.1"]
    names += [n.strip() for n in os.environ.get("TLS_HOSTNAMES", "").split(",") if n.strip()]
    return list(dict.fromkeys(names))


def self_signed(names: list[str], days: int = 397) -> tuple[bytes, bytes, list[x509.Certificate]]:
    key = ec.generate_private_key(ec.SECP256R1())
    sans = []
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0]),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Talos Drift (self-signed)")])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem, [cert]


# --- storage & activation --------------------------------------------------------


def meta() -> dict | None:
    data = vault.get().load(META)
    return json.loads(data) if data else None


def install(fullchain: bytes, key_pem: bytes, info: dict) -> None:
    """Store a certificate and switch the running HTTPS server to it."""
    global _active
    ctx = _new_context(fullchain, key_pem)  # fails before anything is stored
    v = vault.get()
    v.save(CERT, fullchain)
    v.save(KEY, key_pem)
    v.save(META, json.dumps(info).encode())
    _active = ctx
    _set_source(info["source"])
    log.info("installed %s certificate for %s, valid until %s", info["source"], info["names"], info["not_after"])


def _load_into(ctx: ssl.SSLContext, fullchain: bytes, key_pem: bytes) -> None:
    """load_cert_chain needs files: write them to tmpfs for a moment."""
    config.TMP_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=config.TMP_DIR) as d:
        cert_path, key_path = Path(d) / "cert.pem", Path(d) / "key.pem"
        for path, data in ((cert_path, fullchain), (key_path, key_pem)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        try:
            ctx.load_cert_chain(cert_path, key_path)
        except ssl.SSLError as e:
            raise CertError(f"Certificate cannot be loaded: {e.reason or e}") from e


def ensure_certificate() -> None:
    """On first start (or when the self-signed one expires) create a self-signed certificate."""
    info = meta()
    v = vault.get()
    if info and v.exists(CERT) and v.exists(KEY):
        if info["source"] != "selfsigned" or dt.datetime.fromisoformat(info["not_after"]) > _now() + dt.timedelta(days=7):
            return
    names = (info or {}).get("names") or default_names()
    fullchain, key_pem, chain = self_signed(names)
    install(fullchain, key_pem, describe(chain, "selfsigned"))


def _new_context(fullchain: bytes, key_pem: bytes) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["http/1.1"])
    _load_into(ctx, fullchain, key_pem)
    return ctx


def _select_context(ssl_obj: ssl.SSLObject, server_name: str | None, base: ssl.SSLContext) -> None:
    # Called for every ClientHello, also without SNI (server_name is then None).
    if _active is not None and ssl_obj.context is not _active:
        ssl_obj.context = _active


def _set_source(source: str | None) -> None:
    global _active_source
    _active_source = source


def hsts_allowed(host: str | None) -> bool:
    """HSTS only for a trusted certificate on a real hostname.

    HSTS applies to a host on every port, so sending it for localhost or an IP
    would force HTTPS onto unrelated apps on the same machine.
    """
    if _active_source in (None, "selfsigned") or not host or host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return False
    except ValueError:
        return True


def server_context() -> ssl.SSLContext:
    """The SSLContext for the HTTPS server; follows certificate changes without restart."""
    global _active
    v = vault.get()
    _set_source((meta() or {}).get("source"))
    fullchain, key_pem = v.load(CERT), v.load(KEY)
    _active = _new_context(fullchain, key_pem)
    base = _new_context(fullchain, key_pem)
    base.sni_callback = _select_context
    return base


def days_left(info: dict | None = None) -> int | None:
    info = info or meta()
    if not info:
        return None
    return (dt.datetime.fromisoformat(info["not_after"]) - _now()).days

