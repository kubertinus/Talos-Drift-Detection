"""Config patches that are part of the intended baseline.

Patches belong to a cluster. A patch is either uploaded (stored encrypted as
`<cluster>.patch-<id>`) or linked to a file in the cluster's base folder
(`path`, read live). The ordered index with name and target lives in the
encrypted `<cluster>.patches` blob. A patch targets
all nodes, one role, or a single node (by hostname or address).
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


def target_label(target: str) -> str:
    if target == "all":
        return "All nodes"
    if target in ROLES:
        return "Control planes" if target == "controlplane" else "Workers"
    return f"Node {target.removeprefix('node:')}"


def valid_target(target: str) -> bool:
    return target in ("all", *ROLES) or (target.startswith("node:") and len(target) > 5)


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


def set_target(cid: str, patch_id: str, target: str) -> None:
    index = _load(cid)
    for p in index:
        if p["id"] == patch_id:
            p["target"] = target
    _save(cid, index)


def move(cid: str, patch_id: str, step: int) -> None:
    index = _load(cid)
    i = next((i for i, p in enumerate(index) if p["id"] == patch_id), None)
    j = (i or 0) + step
    if i is not None and 0 <= j < len(index):
        index[i], index[j] = index[j], index[i]
        _save(cid, index)


def applicable(role: str, hostname: str, address: str, index: list[dict]) -> list[dict]:
    """Patches for a node, ordered: all nodes, then its role, then node-specific."""
    nodes = {f"node:{hostname}", f"node:{address}"}
    hits = [p for p in index if p["target"] in ("all", role) or p["target"] in nodes]
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
