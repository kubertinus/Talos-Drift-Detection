import os

import pytest

from app.vault import Vault


@pytest.fixture
def vault(tmp_path):
    return Vault("x" * 40, tmp_path / "data", tmp_path / "tmp")


def test_roundtrip_is_encrypted_on_disk(vault):
    vault.save("talosconfig", b"context: secret-stuff")
    raw = (vault.data_dir / "talosconfig.enc").read_bytes()
    assert b"secret-stuff" not in raw
    assert vault.load("talosconfig") == b"context: secret-stuff"
    assert oct(os.stat(vault.data_dir / "talosconfig.enc").st_mode & 0o777) == "0o600"


def test_wrong_key_fails(vault, tmp_path):
    vault.save("worker", b"data")
    other = Vault("y" * 40, vault.data_dir, vault.tmp_dir)
    with pytest.raises(RuntimeError):
        other.load("worker")


def test_materialize_removes_plaintext(vault):
    vault.save("talosconfig", b"plain")
    with vault.materialize("talosconfig") as path:
        assert open(path, "rb").read() == b"plain"
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert not os.path.exists(path)
    assert list(vault.tmp_dir.iterdir()) == []


def test_materialize_cleans_up_on_error(vault):
    vault.save("talosconfig", b"plain")
    with pytest.raises(ValueError):
        with vault.materialize("talosconfig") as path:
            raise ValueError
    assert not os.path.exists(path)


def test_info_never_contains_content(vault):
    vault.save("controlplane", b"machine: {token: zzz}")
    info = vault.info("controlplane")
    assert set(info) == {"fingerprint", "size", "updated"}
