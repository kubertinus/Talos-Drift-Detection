"""Config patches that are part of the intended baseline.

Patches belong to a cluster. A patch is either uploaded (stored encrypted as
`<cluster>.patch-<id>`) or linked to a file in the cluster's base folder
(`path`, read live). The ordered index with name and target lives in the
encrypted `<cluster>.patches` blob. A patch targets all nodes, one role,
a single node (`node:<x>`) or a selection (`nodes:<x>,<y>`), by hostname or address.
"""
import hashlib
import json
import secrets
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone

import yaml

from . import sources, talos, vault
from .store import key

ROLES = ("controlplane", "worker")
# Applied in this order, then in list order within each group.
_GROUP = {"all": 0, "controlplane": 1, "worker": 1}


def _load(cid: str) -> list[dict]:
    data = vault.get().load(key(cid, "patches"))
    return json.loads(data) if data else []


def _save(cid: str, index: list[dict]) -> None:
    vault.get().save(key(cid, "patches"), json.dumps(index).encode())


def all_patches(cid: str) -> list[dict]:
    return _load(cid)


def target_nodes(target: str) -> list[str]:
    """Hostnames/addresses named by a `node:` or `nodes:` target; [] for all/role targets."""
    if target.startswith("node:"):
        return [n for n in [target.removeprefix("node:")] if n]
    if target.startswith("nodes:"):
        return [n for n in target.removeprefix("nodes:").split(",") if n]
    return []


def nodes_target(names: list[str]) -> str:
    names = list(dict.fromkeys(n.strip() for n in names if n.strip()))
    return f"node:{names[0]}" if len(names) == 1 else f"nodes:{','.join(names)}"  # "nodes:" if empty: invalid


def target_label(target: str) -> str:
    if target == "all":
        return "All nodes"
    if target in ROLES:
        return "Control planes" if target == "controlplane" else "Workers"
    names = target_nodes(target)
    return f"Node {names[0]}" if len(names) == 1 else f"Nodes {', '.join(names)}"


def valid_target(target: str) -> bool:
    return target in ("all", *ROLES) or bool(target_nodes(target))


def add(cid: str, name: str, data: bytes, target: str) -> dict:
    index = _load(cid)
    entry = {
        "id": secrets.token_hex(6),
        "name": name,
        "target": target,
        "fingerprint": hashlib.sha256(data).hexdigest()[:16],
        "size": len(data),
        "uploaded": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    vault.get().save(key(cid, f"patch-{entry['id']}"), data)
    index.append(entry)
    _save(cid, index)
    return entry


def add_link(cid: str, rel: str, target: str) -> dict:
    index = _load(cid)
    entry = {
        "id": secrets.token_hex(6),
        "name": rel,
        "path": rel,
        "target": target,
        "uploaded": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    index.append(entry)
    _save(cid, index)
    return entry


def folder(cid: str) -> str:
    """Where new patch files go in the base folder: where the linked patches are (the most used
    folder), else an existing patches/ or patch/ folder, else patch/."""
    dirs = [p["path"].rsplit("/", 1)[0] for p in _load(cid) if p.get("path") and "/" in p["path"]]
    if dirs:
        return max(set(dirs), key=dirs.count)
    base = sources.base_path(cid)
    return next((d for d in ("patches", "patch") if base and (base / d).is_dir()), "patch")


def linked_paths(cid: str) -> set[str]:
    return {p["path"] for p in _load(cid) if p.get("path")}


def delete(cid: str, patch_id: str) -> None:
    _save(cid, [p for p in _load(cid) if p["id"] != patch_id])
    vault.get().delete(key(cid, f"patch-{patch_id}"))


def describe(cid: str, p: dict) -> dict:
    """Patch entry plus live fingerprint/status for the settings page."""
    out = {**p, "label": target_label(p["target"])}
    if p.get("path"):
        try:
            data = sources.read(cid, p["path"])
            out["fingerprint"] = hashlib.sha256(data).hexdigest()[:16]
        except sources.SourceError as e:
            out["error"] = str(e)
    return out


@contextmanager
def _materialize(cid: str, p: dict):
    if p.get("path"):
        yield str(sources.resolve(cid, p["path"]))
    else:
        with vault.get().materialize(key(cid, f"patch-{p['id']}")) as path:
            yield path


def get(cid: str, patch_id: str) -> dict | None:
    return next((p for p in _load(cid) if p["id"] == patch_id), None)


def read(cid: str, p: dict) -> bytes:
    """Current content of a patch (linked file read live, or the encrypted upload)."""
    if p.get("path"):
        return sources.read(cid, p["path"])
    data = vault.get().load(key(cid, f"patch-{p['id']}"))
    if data is None:
        raise sources.SourceError(f"{p['name']} has no stored content")
    return data


def save(cid: str, patch_id: str | None, data: bytes, target: str, name: str = "", path: str = "") -> dict:
    """Store new content for a patch and set its target.

    An existing linked patch is written back to its file; an uploaded one is replaced in the
    vault. A new patch becomes a file in the base folder when `path` is given, else an upload.
    """
    if patch_id is None:
        if path:
            sources.write(cid, path, data)
            return add_link(cid, path, target)
        return add(cid, name or "patch.yaml", data, target)
    index = _load(cid)
    p = next(p for p in index if p["id"] == patch_id)
    if p.get("path"):
        sources.write(cid, p["path"], data)
    else:
        vault.get().save(key(cid, f"patch-{patch_id}"), data)
        p["fingerprint"] = hashlib.sha256(data).hexdigest()[:16]
        p["size"] = len(data)
    p["target"] = target
    p["uploaded"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _save(cid, index)
    return p


def set_target(cid: str, patch_id: str, target: str) -> None:
    index = _load(cid)
    for p in index:
        if p["id"] == patch_id:
            p["target"] = target
    _save(cid, index)


def position(cid: str, patch_id: str) -> int | None:
    return next((i for i, p in enumerate(_load(cid)) if p["id"] == patch_id), None)


def place(cid: str, patch_id: str, index: int) -> None:
    """Move a patch to a list position (order matters: later patches win)."""
    patches_ = _load(cid)
    entry = next(p for p in patches_ if p["id"] == patch_id)
    patches_.remove(entry)
    patches_.insert(min(index, len(patches_)), entry)
    _save(cid, patches_)


def move(cid: str, patch_id: str, step: int) -> None:
    index = _load(cid)
    i = next((i for i, p in enumerate(index) if p["id"] == patch_id), None)
    j = (i or 0) + step
    if i is not None and 0 <= j < len(index):
        index[i], index[j] = index[j], index[i]
        _save(cid, index)


def applicable(role: str, hostname: str, address: str, index: list[dict]) -> list[dict]:
    """Patches for a node, ordered: all nodes, then its role, then node-specific."""
    hits = [p for p in index if p["target"] in ("all", role) or {hostname, address} & set(target_nodes(p["target"]))]
    return sorted(hits, key=lambda p: _GROUP.get(p["target"], 2))  # stable: keeps list order


def check_yaml(data: bytes) -> str | None:
    try:
        docs = [d for d in yaml.safe_load_all(data) if d is not None]
    except yaml.YAMLError as e:
        # Don't echo the parser message: it can quote file content.
        mark = getattr(e, "problem_mark", None)
        return f"Invalid YAML (line {mark.line + 1})" if mark else "Invalid YAML"
    if not docs or not all(isinstance(d, (dict, list)) for d in docs):
        return "No patch found (expected a strategic merge or JSON6902 patch)."
    return None


async def build_baseline(cid: str, role: str, patch_list: list[dict]) -> str:
    """Role baseline with the given patches applied; raises TalosError on failure."""
    with ExitStack() as stack:
        try:
            base = stack.enter_context(sources.materialize(cid, role))
            paths = [stack.enter_context(_materialize(cid, p)) for p in patch_list]
            return await talos.patch_config(base, paths)
        except (talos.TalosError, sources.SourceError) as e:
            names = ", ".join(p["name"] for p in patch_list)
            raise talos.TalosError(f"Patches ({names}) cannot be applied: {e}") from e


async def try_apply(cid: str, data: bytes, target: str, node_role: str | None = None) -> str | None:
    """Dry-run a new patch on the baseline(s) it targets; returns an error message or None.

    A patch for all nodes must fit every uploaded baseline; one for a single
    node only has to fit that node's role (or any role, if it's not known yet).
    """
    v = vault.get()
    if target in ROLES:
        roles = [target]
    elif target.startswith("node:") and node_role in ROLES:
        roles = [node_role]
    else:
        roles = list(ROLES)
    roles = [r for r in roles if sources.exists(cid, r)]
    tmp_id = f"dryrun-{secrets.token_hex(4)}"
    tmp = key(cid, f"patch-{tmp_id}")
    v.save(tmp, data)
    errors = {}
    try:
        for role in roles:
            try:
                await build_baseline(cid, role, [{"id": tmp_id, "name": "new patch"}])
            except talos.TalosError as e:
                errors[role] = str(e).split(": ", 1)[-1]
    finally:
        v.delete(tmp)
    if not errors or (target.startswith("node:") and len(errors) < len(roles)):
        return None
    role, msg = next(iter(errors.items()))
    return f"Patch does not apply to {role}.yaml: {msg}"
