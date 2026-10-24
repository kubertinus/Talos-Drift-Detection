"""Collect configs from all nodes of a cluster and compute drift against the baselines."""
import asyncio
import logging
from datetime import datetime, timezone

import yaml

from . import config, drift, patches, sources, store, talos

log = logging.getLogger("scanner")
_locks: dict[str, asyncio.Lock] = {}
_rerun: set[str] = set()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _lock(cid: str) -> asyncio.Lock:
    return _locks.setdefault(cid, asyncio.Lock())


def is_running(cid: str) -> bool:
    return _lock(cid).locked()


def running() -> list[str]:
    return [cid for cid, lock in _locks.items() if lock.locked()]


def request(cid: str) -> None:
    """Start a scan, or queue one more if one is running (settings may have changed mid-scan)."""
    if is_running(cid):
        _rerun.add(cid)
    else:
        asyncio.create_task(run(cid))


async def _targets(tc_path: str, tc_text: str, settings: dict) -> tuple[list[dict], str | None, bool]:
    """Nodes to scan, an error message, and whether to connect to nodes directly.

    A freshly generated talosconfig has no endpoints; then every node is used
    as its own endpoint and discovery runs via the first configured node.
    """
    manual = [n.strip() for n in settings.get("nodes", []) if n.strip()]
    endpoints, ctx_nodes = talos.context_nodes(tc_text)
    direct = not endpoints
    via = settings.get("discovery_node") or (ctx_nodes or endpoints or manual or [None])[0]
    if via:
        try:
            members = await talos.discover(tc_path, via, direct)
            if members:
                known = {a for m in members for a in m.get("addresses", [m["address"]])}
                members += [{"address": a, "hostname": a, "role": "unknown"} for a in manual if a not in known]
                return members, None, direct
        except talos.TalosError as e:
            log.warning("discovery via %s failed: %s", via, e)
            if not manual:
                return [], f"Discovery via {via} failed: {e}", direct
    if not manual:
        hint = " The talosconfig has no endpoints." if direct else ""
        return [], f"No nodes found: set a discovery node or a manual node list.{hint}", direct
    return [{"address": a, "hostname": a, "role": "unknown"} for a in manual], None, direct


class Baselines:
    """Role baselines with applicable patches, built once per distinct patch set."""

    def __init__(self, cid: str, raw: dict[str, str], patch_index: list[dict]):
        self.cid = cid
        self.raw = raw
        self.index = patch_index
        self._built: dict[tuple, asyncio.Task] = {}

    async def get(self, role: str, hostname: str, address: str) -> tuple[str | None, list[str]]:
        if role not in self.raw:
            return None, []
        applied = patches.applicable(role, hostname, address, self.index)
        if not applied:
            return self.raw[role], []
        key = (role, *(p["id"] for p in applied))
        if key not in self._built:
            self._built[key] = asyncio.create_task(patches.build_baseline(self.cid, role, applied))
        return await self._built[key], [p["name"] for p in applied]


async def _scan_node(sem, tc_path: str, member: dict, baselines: Baselines, ignore: list[str], direct: bool) -> dict:
    node = {**member, "scanned_at": _now()}
    async with sem:
        try:
            actual = await talos.machine_config(tc_path, member["address"], direct)
            if not node.get("talos_version"):
                node["talos_version"] = await talos.version(tc_path, member["address"], direct)
        except talos.TalosError as e:
            return {**node, "status": "unreachable", "error": str(e), "signature": None, "shape": None}

    docs = drift.parse_config(actual)
    node["config"] = actual  # unmasked, as talosctl returned it; only stored encrypted
    # Never identify a node by a floating VIP: it moves to another node on failover.
    shared = drift.vips(docs)
    if node["address"] in shared:
        own = [a for a in member.get("addresses", []) if a not in shared]
        node["vip"] = node["address"]
        node["address"] = own[0] if own else node["address"]
    main = docs.get("", {})
    machine = main.get("machine") or {}
    node["role"] = machine.get("type") or node.get("role", "unknown")
    if node["role"] == "init":
        node["role"] = "controlplane"
    if not node.get("hostname") or node["hostname"] == node["address"]:
        node["hostname"] = (machine.get("network") or {}).get("hostname") or node["address"]

    try:
        baseline, applied = await baselines.get(node["role"], node["hostname"], node["address"])
    except talos.TalosError as e:
        return {**node, "status": "patch-error", "error": str(e), "signature": None, "shape": None}
    if baseline is None:
        return {**node, "status": "no-baseline", "changes": [], "diff": "", "signature": None, "shape": None}
    result = drift.compute(baseline, actual, ignore)
    return {
        **node,
        "patches": applied,
        "status": "drift" if result["changes"] else "in-sync",
        "drift_count": len(result["changes"]),
        "changes": result["changes"],
        "ignored": result["ignored"],
        "diff": result["diff"],
        "signature": drift.signature(result["changes"]),
        "shape": drift.shape(result["changes"]),
    }


async def _scan_once(cid: str) -> dict:
    settings = store.settings(cid)
    scan = {"started_at": _now(), "nodes": [], "error": None}
    raw = {}
    try:
        for role in ("controlplane", "worker"):
            data = sources.load(cid, role)
            if data:
                raw[role] = data.decode()
        tc_text = sources.load(cid, "talosconfig")
    except sources.SourceError as e:
        tc_text = None
        scan["error"] = str(e)
    baselines = Baselines(cid, raw, patches.all_patches(cid))
    if not tc_text:
        scan["error"] = scan["error"] or "No talosconfig uploaded or linked."
    else:
        with sources.materialize(cid, "talosconfig") as tc_path:
            members, err, direct = await _targets(tc_path, tc_text.decode(), settings)
            scan["error"] = err
            sem = asyncio.Semaphore(config.SCAN_CONCURRENCY)
            scan["nodes"] = await asyncio.gather(
                *(_scan_node(sem, tc_path, m, baselines, settings["ignore"], direct) for m in members)
            )
    drift.mark_outliers(scan["nodes"])
    scan["nodes"].sort(key=lambda n: (n.get("role", ""), n.get("hostname", "")))
    scan["finished_at"] = _now()
    if store.get_cluster(cid):  # the cluster may have been deleted mid-scan
        store.add_scan(cid, scan)
    log.info("scan %s finished: %d nodes, error=%s", cid, len(scan["nodes"]), scan["error"])
    return scan


async def run(cid: str) -> dict | None:
    """Scan one cluster. Concurrent callers wait for the running scan."""
    lock = _lock(cid)
    if lock.locked():
        async with lock:
            return store.latest(cid)
    async with lock:
        while True:
            _rerun.discard(cid)
            scan = await _scan_once(cid)
            if cid not in _rerun:
                return scan


def _due(cid: str) -> bool:
    last = store.latest(cid)
    if not last or not last.get("finished_at"):
        return True
    interval = max(60, int(store.settings(cid).get("scan_interval", config.DEFAULT_SCAN_INTERVAL)))
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(last["finished_at"])).total_seconds()
    return age >= interval


async def loop() -> None:
    """Scan every cluster whenever its own interval has passed."""
    while True:
        for c in store.clusters():
            try:
                if not is_running(c["id"]) and _due(c["id"]):
                    asyncio.create_task(run(c["id"]))
            except Exception:
                log.exception("scheduling scan for %s failed", c["id"])
        await asyncio.sleep(30)


def validate_upload(kind: str, data: bytes) -> str | None:
    """Return an error message if an uploaded file doesn't look right."""
    try:
        docs = list(yaml.safe_load_all(data))
    except yaml.YAMLError as e:
        # Don't echo the parser message: it can quote file content (secrets).
        mark = getattr(e, "problem_mark", None)
        return f"Invalid YAML (line {mark.line + 1})" if mark else "Invalid YAML"
    if kind == "talosconfig":
        d = docs[0] if docs else None
        if not isinstance(d, dict) or "contexts" not in d:
            return "This does not look like a talosconfig (no 'contexts')."
        return None
    main = next((d for d in docs if isinstance(d, dict) and d.get("version") == "v1alpha1"), None)
    if not main:
        return "No v1alpha1 machine config document found."
    mtype = (main.get("machine") or {}).get("type")
    expected = {"controlplane": ("controlplane", "init"), "worker": ("worker",)}[kind]
    if mtype not in expected:
        return f"machine.type is '{mtype}', expected {expected[0]}."
    return None
