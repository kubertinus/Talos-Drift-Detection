"""Clusters, their settings and scan history, all stored encrypted through the vault.

Per-cluster blobs are named `<cluster id>.<name>` (settings, results, patches,
uploaded talosconfig/controlplane/worker).
"""
import json
import re
import secrets

from . import config, drift, vault

CLUSTERS = "clusters"
LEGACY = ("settings", "results", "patches", "talosconfig", "controlplane", "worker")


def key(cid: str, name: str) -> str:
    return f"{cid}.{name}"


def _load(name: str, default):
    data = vault.get().load(name)
    return json.loads(data) if data else default


def _save(name: str, value) -> None:
    vault.get().save(name, json.dumps(value).encode())


# --- clusters ------------------------------------------------------------


def clusters() -> list[dict]:
    return _load(CLUSTERS, [])


def get_cluster(cid: str) -> dict | None:
    return next((c for c in clusters() if c["id"] == cid), None)


def _new_id(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:24] or "cluster"
    return f"{slug}-{secrets.token_hex(3)}"


def add_cluster(name: str) -> dict:
    cs = clusters()
    cluster = {"id": _new_id(name), "name": name}
    cs.append(cluster)
    _save(CLUSTERS, cs)
    return cluster


def rename_cluster(cid: str, name: str) -> None:
    cs = clusters()
    for c in cs:
        if c["id"] == cid:
            c["name"] = name
    _save(CLUSTERS, cs)


def delete_cluster(cid: str) -> None:
    _save(CLUSTERS, [c for c in clusters() if c["id"] != cid])
    vault.get().delete_prefix(f"{cid}.")


def migrate_legacy() -> None:
    """Move single-cluster data from before multi-cluster support into a cluster."""
    v = vault.get()
    if v.exists(CLUSTERS) or not any(v.exists(n) for n in LEGACY):
        return
    old = _load("settings", {})
    name = (old.get("base_dir") or "").rstrip("/").split("/")[-1] or "cluster"
    cluster = add_cluster(name)
    for n in LEGACY:
        v.rename(n, key(cluster["id"], n))
    for path in v.data_dir.glob("patch-*.enc"):
        n = path.name.removesuffix(".enc")
        v.rename(n, key(cluster["id"], n))


# --- per cluster ---------------------------------------------------------


def settings(cid: str) -> dict:
    s = _load(key(cid, "settings"), {})
    s.setdefault("ignore", list(drift.DEFAULT_IGNORE))
    s.setdefault("scan_interval", config.DEFAULT_SCAN_INTERVAL)
    s.setdefault("nodes", [])
    s.setdefault("discovery_node", "")
    s.setdefault("files", {})
    s.setdefault("base_dir", "")
    return s


def save_settings(cid: str, s: dict) -> None:
    _save(key(cid, "settings"), s)


def history(cid: str) -> list[dict]:
    return _load(key(cid, "results"), [])


def latest(cid: str) -> dict | None:
    h = history(cid)
    return h[-1] if h else None


def add_scan(cid: str, scan: dict) -> None:
    h = history(cid)
    prev = {n["address"]: n for n in h[-1]["nodes"]} if h else {}
    for n in scan["nodes"]:
        p = prev.get(n["address"])
        if n.get("status") != "drift":
            n["drift_since"] = None
        elif p and p.get("status") == "drift" and p.get("signature") == n.get("signature"):
            n["drift_since"] = p.get("drift_since") or p.get("scanned_at")
        else:
            n["drift_since"] = scan["finished_at"]
    h.append(scan)
    # Only the latest scan keeps full diffs; older entries are trimmed to a summary.
    for old in h[:-1]:
        for n in old["nodes"]:
            n.pop("diff", None)
            n.pop("changes", None)
            n.pop("ignored", None)
            n.pop("config", None)
    _save(key(cid, "results"), h[-config.HISTORY_SIZE :])
