"""Where the talosconfig, baselines and patches come from.

A file is either uploaded (stored encrypted in the vault) or linked to a
path in the base folder. CONFIG_DIR is a read-only mount of a directory on
the Docker host (e.g. the home directory); the base folder is a directory
inside it chosen in the UI. Links are stored relative to the base folder and
read live on every scan, so edits on the host are picked up. Hidden files and
directories (.ssh, .talos, ...) are never listed or opened.
"""
import hashlib
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import config, store, vault
from .store import key

MAX_SIZE = 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


class SourceError(Exception):
    pass


def available() -> bool:
    return config.CONFIG_DIR.is_dir()


def _hidden(rel: Path) -> bool:
    return any(part.startswith(".") for part in rel.parts)


def _inside(root: Path, rel: str) -> Path | None:
    """Resolved path of rel under root, or None if it escapes root or is hidden."""
    path = (root / rel).resolve()
    if path != root and root not in path.parents:
        return None
    if _hidden(path.relative_to(root)):
        return None
    return path


def base_dir(cid: str) -> str:
    return store.settings(cid).get("base_dir", "")


def set_base_dir(cid: str, rel: str) -> None:
    s = store.settings(cid)
    s["base_dir"] = rel.strip("/")
    store.save_settings(cid, s)


def base_path(cid: str) -> Path | None:
    """The cluster's base folder, if set and present."""
    rel = base_dir(cid)
    if not rel or not available():
        return None
    path = _inside(config.CONFIG_DIR.resolve(), rel)
    return path if path and path.is_dir() else None


def resolve(cid: str, rel: str) -> Path:
    """File inside the base folder; refuses anything that escapes it (.., symlinks) or is hidden."""
    base = base_path(cid)
    path = _inside(base, rel) if base else None
    if not path or not path.is_file():
        raise SourceError(f"{rel} niet gevonden in basismap {base_dir(cid) or '(niet ingesteld)'}")
    return path


def list_dirs(rel: str = "") -> dict:
    """Non-hidden subdirectories of a folder under CONFIG_DIR, for the folder picker."""
    root = config.CONFIG_DIR.resolve()
    path = _inside(root, rel) if available() else None
    if not path or not path.is_dir():
        raise SourceError(f"Map {rel or '/'} niet gevonden")
    dirs = []
    try:
        entries = sorted(path.iterdir(), key=lambda p: p.name.lower())
    except OSError as e:
        raise SourceError(f"Map {rel or '/'} niet leesbaar: {e.strerror}") from e
    for p in entries:
        if p.name.startswith(".") or not _safe_is_dir(p) or not _inside(root, str(p.relative_to(root))):
            continue
        dirs.append({"name": p.name, "path": str(p.relative_to(root)), "talos": _looks_like_cluster(p)})
    current = "" if path == root else str(path.relative_to(root))
    parent = None
    if current:
        parent = str(Path(current).parent)
        parent = "" if parent == "." else parent
    return {"path": current, "parent": parent, "dirs": dirs}


def _safe_is_dir(p: Path) -> bool:
    try:
        return p.is_dir()
    except OSError:
        return False


def _looks_like_cluster(p: Path) -> bool:
    candidates = ("talosconfig", "controlplane.yaml", "_out/talosconfig", "_out/controlplane.yaml")
    try:
        return any((p / c).is_file() for c in candidates)
    except OSError:
        return False


def read(cid: str, rel: str) -> bytes:
    path = resolve(cid, rel)
    if path.stat().st_size > MAX_SIZE:
        raise SourceError(f"{rel} is groter dan 1 MB")
    return path.read_bytes()


MAX_FILES = 500


def list_files(cid: str) -> list[str]:
    """Relative paths of candidate files in the base folder (small, non-hidden)."""
    root = base_path(cid)
    if not root:
        return []
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        if len(Path(dirpath).relative_to(root).parts) >= 5:
            dirnames[:] = []
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            p = Path(dirpath) / name
            try:
                if root in p.resolve().parents and p.stat().st_size <= MAX_SIZE:
                    out.append(str(p.relative_to(root)))
            except OSError:
                continue
            if len(out) >= MAX_FILES:
                return out
    return out


# --- talosconfig / controlplane / worker -----------------------------------


def linked(cid: str, kind: str) -> str | None:
    return store.settings(cid).get("files", {}).get(kind)


def link(cid: str, kind: str, rel: str | None) -> None:
    s = store.settings(cid)
    files = s.setdefault("files", {})
    if rel:
        files[kind] = rel
    else:
        files.pop(kind, None)
    store.save_settings(cid, s)


def save_upload(cid: str, kind: str, data: bytes) -> None:
    vault.get().save(key(cid, kind), data)
    link(cid, kind, None)


def remove(cid: str, kind: str) -> None:
    vault.get().delete(key(cid, kind))
    link(cid, kind, None)


def load(cid: str, kind: str) -> bytes | None:
    rel = linked(cid, kind)
    if rel:
        return read(cid, rel)
    return vault.get().load(key(cid, kind))


def exists(cid: str, kind: str) -> bool:
    rel = linked(cid, kind)
    if rel:
        try:
            resolve(cid, rel)
            return True
        except SourceError:
            return False
    return vault.get().exists(key(cid, kind))


def info(cid: str, kind: str) -> dict | None:
    rel = linked(cid, kind)
    if not rel:
        i = vault.get().info(key(cid, kind))
        return {**i, "source": "upload"} if i else None
    try:
        path = resolve(cid, rel)
        data = path.read_bytes()
    except (SourceError, OSError) as e:
        return {"source": "file", "path": rel, "error": str(e)}
    return {
        "source": "file",
        "path": rel,
        "fingerprint": hashlib.sha256(data).hexdigest()[:16],
        "size": len(data),
        "updated": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(timespec="seconds"),
    }


@contextmanager
def materialize(cid: str, kind: str):
    """Path for talosctl: the linked file itself, or a temporary decrypted copy."""
    rel = linked(cid, kind)
    if rel:
        yield str(resolve(cid, rel))
    else:
        with vault.get().materialize(key(cid, kind)) as path:
            yield path
