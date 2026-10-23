"""Encrypted storage for talosconfig, baseline configs and scan results.

Everything on disk under DATA_DIR is Fernet-encrypted with a key derived
from MASTER_KEY. Plaintext only ever touches TMP_DIR (tmpfs in compose)
for the duration of a talosctl call.
"""
import base64
import hashlib
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import config

SECRETS = ("talosconfig", "controlplane", "worker")


class Vault:
    def __init__(self, master_key: str, data_dir: Path, tmp_dir: Path):
        raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"talos-drift", info=b"vault-v1").derive(
            master_key.encode()
        )
        self._fernet = Fernet(base64.urlsafe_b64encode(raw))
        self.data_dir = data_dir
        self.tmp_dir = tmp_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        return self.data_dir / f"{name}.enc"

    def save(self, name: str, data: bytes) -> None:
        path = self._path(name)
        tmp = path.with_suffix(".enc.tmp")
        tmp.write_bytes(self._fernet.encrypt(data))
        os.chmod(tmp, 0o600)
        tmp.replace(path)

    def load(self, name: str) -> bytes | None:
        path = self._path(name)
        if not path.exists():
            return None
        try:
            return self._fernet.decrypt(path.read_bytes())
        except InvalidToken as e:
            raise RuntimeError(f"Cannot decrypt {name}: wrong MASTER_KEY?") from e

    def exists(self, name: str) -> bool:
        return self._path(name).exists()

    def delete(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)

    def rename(self, old: str, new: str) -> None:
        if self._path(old).exists():
            self._path(old).replace(self._path(new))

    def delete_prefix(self, prefix: str) -> None:
        for p in self.data_dir.glob(f"{prefix}*.enc"):
            p.unlink(missing_ok=True)

    def info(self, name: str) -> dict | None:
        """Metadata safe to show in the UI: never the content itself."""
        data = self.load(name)
        if data is None:
            return None
        mtime = datetime.fromtimestamp(self._path(name).stat().st_mtime, timezone.utc)
        return {
            "fingerprint": hashlib.sha256(data).hexdigest()[:16],
            "size": len(data),
            "updated": mtime.isoformat(timespec="seconds"),
        }

    @contextmanager
    def materialize(self, name: str):
        """Yield a path to a 0600 plaintext copy that is removed afterwards."""
        data = self.load(name)
        if data is None:
            raise FileNotFoundError(f"{name} has not been uploaded")
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix=f"{name}-", dir=self.tmp_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            yield path
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


_vault: Vault | None = None


def get() -> Vault:
    global _vault
    if _vault is None:
        _vault = Vault(config.MASTER_KEY, config.DATA_DIR, config.TMP_DIR)
    return _vault
