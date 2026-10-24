"""Generate the machine config for a new node of a cluster.

The config is what the baseline says such a node should have: the role config with every patch
for all nodes and for the role, plus a node-specific patch for the new node (usually copied from
an existing node, with its hostname and address replaced). It is only generated while the
cluster has no unplanned drift, so a new node never starts out from a config the running nodes
do not have.
"""
import re
import secrets
import time
from datetime import datetime, timezone

import yaml

from . import drift, patches, sources, store, talos, vault
from .store import key

MODES = ("metal", "cloud", "container")
DOWNLOAD_TTL = 10 * 60
SCAN_MAX_AGE = 3600
HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_downloads: dict[str, dict] = {}


class NodeGenError(Exception):
    pass


def readiness(cid: str) -> tuple[list[str], list[str]]:
    """(blockers, warnings): generating is refused while there is unplanned drift."""
    scan = store.latest(cid)
    if not scan:
        return ["No scan yet: scan the cluster first."], []
    blockers, warnings = [], []
    if scan.get("error"):
        blockers.append(f"The latest scan failed: {scan['error']}")
    bad = [n for n in scan["nodes"] if n["status"] in ("drift", "patch-error", "no-baseline")]
    if bad:
        blockers.append("Unplanned drift: " + ", ".join(f"{n['hostname']} ({n['status']})" for n in bad)
                        + ". Fix it (e.g. Sync nodes to baseline) first.")
    unplanned = [(role, d["path"]) for role, diffs in (scan.get("peers") or {}).items() for d in diffs if not d["intended"]]
    if unplanned:
        blockers.append(f"{len(unplanned)} unplanned difference(s) between nodes of the same role (see Consistency).")
    down = [n["hostname"] for n in scan["nodes"] if n["status"] == "unreachable"]
    if down:
        warnings.append(f"Unreachable in the latest scan: {', '.join(down)}; their config could not be checked.")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(scan["finished_at"])).total_seconds() if scan.get("finished_at") else 0
    if age > SCAN_MAX_AGE:
        warnings.append(f"The latest scan is {int(age // 60)} minutes old; consider Scan now first.")
    return blockers, warnings


def _node_patches(cid: str, n: dict) -> list[dict]:
    """The patches that target this node specifically (not all nodes or its role)."""
    return [p for p in patches.all_patches(cid) if {n["hostname"], n["address"]} & set(patches.target_nodes(p["target"]))]


def templates(cid: str, role: str) -> list[dict]:
    """Existing nodes of a role, with the names of their node-specific patches."""
    nodes = [n for n in (store.latest(cid) or {}).get("nodes", []) if n.get("role") == role]
    return [{"hostname": n["hostname"], "address": n["address"], "patches": [p["name"] for p in _node_patches(cid, n)]}
            for n in sorted(nodes, key=lambda n: n["hostname"])]


def template_text(cid: str, template: str, hostname: str, address: str) -> str:
    """The template node's own patches, with its hostname and address replaced by the new ones."""
    n = next((n for n in (store.latest(cid) or {}).get("nodes", []) if n["hostname"] == template), None)
    if not n:
        raise NodeGenError(f"{template} is not in the latest scan")
    docs = []
    for p in _node_patches(cid, n):
        try:
            docs.append(patches.read(cid, p).decode().strip())
        except sources.SourceError as e:
            raise NodeGenError(str(e)) from e
    text = "\n---\n".join(d.removeprefix("---").strip() for d in docs if d) + "\n" if docs else ""
    if hostname:
        text = re.sub(rf"(?<![\w.-]){re.escape(n['hostname'])}(?![\w-])", hostname, text)
    if address:
        text = re.sub(rf"(?<![\d.]){re.escape(n['address'])}(?![\d])", address, text)
    return text


async def generate(cid: str, role: str, hostname: str, address: str, node_patch: str, mode: str = "metal",
                   reference: str = "") -> dict:
    """Build and validate the config; returns a masked preview and a one-time download id."""
    blockers, warnings = readiness(cid)
    if blockers:
        raise NodeGenError(" ".join(blockers))
    existing = existing_node_patches(cid, hostname.strip().lower())
    if existing:
        warnings = [*warnings, f"{hostname} already has a node patch in the baseline ({', '.join(existing)}); "
                               "it is not used for this config. Remove it if it is left over."]
    if role not in patches.ROLES:
        raise NodeGenError("Choose control plane or worker")
    if mode not in MODES:
        raise NodeGenError(f"Unknown mode {mode}")
    hostname = hostname.strip().lower()
    if not HOSTNAME.fullmatch(hostname):
        raise NodeGenError("Enter a valid hostname (lowercase letters, digits and dashes)")
    known = {n["hostname"] for n in store.latest(cid)["nodes"]} | {n["address"] for n in store.latest(cid)["nodes"]}
    if hostname in known or (address and address in known):
        raise NodeGenError(f"{hostname if hostname in known else address} is already a node of this cluster")
    if not sources.exists(cid, role):
        raise NodeGenError(f"No {role}.yaml for this cluster")
    data = node_patch.replace("\r\n", "\n").encode()
    if data.strip():
        error = patches.check_yaml(data)
        if error:
            raise NodeGenError(f"Node patch: {error}")

    v = vault.get()
    tmp_id = f"newnode-{secrets.token_hex(4)}"
    index = [p for p in patches.all_patches(cid) if not patches.target_nodes(p["target"])]  # all nodes + role
    if data.strip():
        index.append({"id": tmp_id, "name": f"{hostname} (new node)", "target": f"node:{hostname}"})
        v.save(key(cid, f"patch-{tmp_id}"), data)
    try:
        applied = patches.applicable(role, hostname, address, index)
        try:
            config = await patches.build_baseline(cid, role, applied)
        except talos.TalosError as e:
            raise NodeGenError(str(e)) from e
    finally:
        v.delete(key(cid, f"patch-{tmp_id}"))
    # Like the running nodes: drop ignored paths and empty defaults that an existing node of the
    # role does not have (e.g. cluster.proxy, which Talos moves into a KubeProxyConfig document).
    ref = _reference(cid, role, reference)
    if ref:
        config = drift.keep_ignored(config, ref["config"], store.settings(cid)["ignore"], take=False)
    else:
        warnings = [*warnings, f"No reachable {role} to compare with; the config is the plain baseline."]
    docs = [d for d in yaml.safe_load_all(config) if isinstance(d, dict)]
    names = {d.get("hostname") for d in docs if d.get("kind") == "HostnameConfig"}
    names.add(((docs[0].get("machine") or {}).get("network") or {}).get("hostname") if docs else None)
    if hostname not in names:
        warnings = [*warnings, f"Nothing in this config sets the hostname {hostname} (no HostnameConfig or "
                               "machine.network.hostname): Talos would pick one itself. Add it to the node patch."]
    try:
        await talos.validate_config(config, mode)
    except talos.TalosError as e:
        raise NodeGenError(f"talosctl validate ({mode}): {e}") from e

    _prune()
    download_id = secrets.token_urlsafe(12)
    _downloads[download_id] = {"cid": cid, "hostname": hostname, "config": config, "expires": time.monotonic() + DOWNLOAD_TTL}
    return {
        "download_id": download_id, "hostname": hostname, "role": role, "mode": mode, "warnings": warnings,
        "reference": ref["hostname"] if ref else None,
        "patches": [p["name"] for p in applied],
        "preview": drift.to_yaml(drift.mask_docs(drift.parse_config(config))),
    }


def _reference(cid: str, role: str, preferred: str) -> dict | None:
    """An existing node of the role with its config from the latest scan (the template node first)."""
    nodes = [n for n in (store.latest(cid) or {}).get("nodes", []) if n.get("role") == role and n.get("config")]
    return next((n for n in nodes if n["hostname"] == preferred), nodes[0] if nodes else None)


def download(cid: str, download_id: str) -> tuple[str, str]:
    """(hostname, config) of a generated config; usable once, within DOWNLOAD_TTL."""
    _prune()
    d = _downloads.pop(download_id, None)
    if not d or d["cid"] != cid:
        raise NodeGenError("This generated config has expired or was already downloaded; generate it again.")
    return d["hostname"], d["config"]


def existing_node_patches(cid: str, hostname: str) -> list[str]:
    return [p["name"] for p in patches.all_patches(cid) if hostname in patches.target_nodes(p["target"])]


def save_node_patch(cid: str, hostname: str, node_patch: str) -> dict:
    """Register the node patch for the new node (target node:<hostname>): as patch/<hostname>.yaml in
    the base folder when possible, else stored in the app. Never twice, never over an existing file."""
    existing = existing_node_patches(cid, hostname)
    if existing:
        raise NodeGenError(f"{hostname} already has a node patch ({', '.join(existing)}); not registered again.")
    data = node_patch.replace("\r\n", "\n").encode()
    path = f"patch/{hostname}.yaml"
    if sources.base_path(cid):
        if sources.base_path(cid).joinpath(path).exists():
            raise NodeGenError(f"{path} already exists in the base folder; link it under Settings → Patches, "
                               "or delete it first. Not registered.")
        try:
            sources.check_writable(cid, path, "create")
            return patches.save(cid, None, data, f"node:{hostname}", path=path)
        except sources.SourceError:
            pass  # base folder not writable: store it in the app instead
    return patches.save(cid, None, data, f"node:{hostname}", name=f"{hostname}.yaml")


def _prune() -> None:
    now = time.monotonic()
    for k in [k for k, d in _downloads.items() if d["expires"] < now]:
        del _downloads[k]
