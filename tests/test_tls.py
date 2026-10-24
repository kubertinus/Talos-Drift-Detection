import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app import config, tls, vault
from app.vault import Vault

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, key, issuer_cn, issuer_key, ca, days=30, start=None):
    start = start or NOW - dt.timedelta(days=1)
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def _key_pem(key, password=None):
    enc = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


@pytest.fixture(scope="module")
def pki():
    root_key, int_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Test Root", root_key, "Test Root", root_key, ca=True, days=3650)
    inter = _cert("Test Intermediate", int_key, "Test Root", root_key, ca=True, days=1000)
    leaf = _cert("drift.example.com", leaf_key, "Test Intermediate", int_key, ca=False)
    return {"root": root, "inter": inter, "leaf": leaf, "leaf_key": leaf_key, "int_key": int_key}


@pytest.fixture
def v(tmp_path, monkeypatch):
    instance = Vault("x" * 40, tmp_path / "data", tmp_path / "tmp")
    monkeypatch.setattr(vault, "_vault", instance)
    monkeypatch.setattr(config, "TMP_DIR", tmp_path / "tmp")
    monkeypatch.setattr(tls, "_active", None)
    return instance


def test_chain_is_ordered_and_root_not_served(pki):
    # Root before intermediate, all in the "chain" field: order shouldn't matter.
    fullchain, key, chain = tls.prepare(_pem(pki["leaf"]), _key_pem(pki["leaf_key"]), _pem(pki["root"], pki["inter"]))
    assert [tls._cn(c) for c in chain] == ["drift.example.com", "Test Intermediate", "Test Root"]
    served = x509.load_pem_x509_certificates(fullchain)
    assert [tls._cn(c) for c in served] == ["drift.example.com", "Test Intermediate"]
    info = tls.describe(chain, "upload")
    assert info["names"] == ["drift.example.com"] and info["issuer"] == "Test Intermediate"


def test_everything_in_one_file(pki):
    _, _, chain = tls.prepare(_pem(pki["inter"], pki["leaf"], pki["root"]), _key_pem(pki["leaf_key"]))
    assert len(chain) == 3


def test_wrong_key(pki):
    with pytest.raises(tls.CertError, match="does not match any"):
        tls.prepare(_pem(pki["leaf"]), _key_pem(ec.generate_private_key(ec.SECP256R1())))


def test_expired(pki):
    old = _cert("old.example.com", pki["leaf_key"], "Test Intermediate", pki["int_key"], ca=False, days=10,
                start=NOW - dt.timedelta(days=100))
    with pytest.raises(tls.CertError, match="expired"):
        tls.prepare(_pem(old), _key_pem(pki["leaf_key"]))


def test_bad_signature(pki):
    other_key = ec.generate_private_key(ec.SECP256R1())
    fake_inter = _cert("Test Intermediate", other_key, "Test Root", other_key, ca=True)
    with pytest.raises(tls.CertError, match="not signed"):
        tls.prepare(_pem(pki["leaf"]), _key_pem(pki["leaf_key"]), _pem(fake_inter))


def test_encrypted_key(pki):
    key = _key_pem(pki["leaf_key"], "s3cret")
    with pytest.raises(tls.CertError, match="passphrase"):
        tls.prepare(_pem(pki["leaf"]), key)
    fullchain, key_out, _ = tls.prepare(_pem(pki["leaf"]), key, passphrase="s3cret")
    assert b"ENCRYPTED" not in key_out


def test_garbage():
    with pytest.raises(tls.CertError):
        tls.prepare(b"not a cert", b"not a key")


def _served_cn(port: int, sni: str | None = None) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port)) as raw, ctx.wrap_socket(raw, server_hostname=sni) as s:
        return tls._cn(x509.load_der_x509_certificate(s.getpeercert(binary_form=True)))


def test_first_start_and_hot_swap(v, pki):
    tls.ensure_certificate()
    assert tls.meta()["source"] == "selfsigned"
    ctx = tls.server_context()

    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        assert _served_cn(port) == "localhost"
        fullchain, key, chain = tls.prepare(_pem(pki["leaf"], pki["inter"]), _key_pem(pki["leaf_key"]))
        tls.install(fullchain, key, tls.describe(chain, "upload"))
        assert _served_cn(port) == "drift.example.com"  # same server context, new certificate, no restart
        assert _served_cn(port, sni="drift.example.com") == "drift.example.com"

        # An RSA certificate must replace the EC one, not be added next to it.
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_leaf = _cert("rsa.example.com", rsa_key, "Test Intermediate", pki["int_key"], ca=False)
        fullchain, key, chain = tls.prepare(_pem(rsa_leaf, pki["inter"]), _key_pem(rsa_key))
        tls.install(fullchain, key, tls.describe(chain, "upload"))
        assert _served_cn(port) == "rsa.example.com"
    finally:
        stop.set()
        t.join()
        listener.close()
    assert tls.meta()["source"] == "upload"
    tls.ensure_certificate()  # an uploaded certificate is never replaced by a self-signed one
    assert tls.meta()["source"] == "upload"
    assert not any(v.tmp_dir.iterdir())  # no plaintext key left behind


@pytest.mark.parametrize(
    "source, host, ok",
    [
        ("selfsigned", "drift.example.com", False),
        ("upload", "localhost", False),
        ("upload", "127.0.0.1", False),
        ("letsencrypt", "[::1]", False),
        ("upload", "drift.example.com", True),
        ("letsencrypt", "drift.example.com", True),
    ],
)
def test_hsts_only_for_trusted_cert_on_hostname(monkeypatch, source, host, ok):
    monkeypatch.setattr(tls, "_active_source", source)
    assert tls.hsts_allowed(host) is ok
