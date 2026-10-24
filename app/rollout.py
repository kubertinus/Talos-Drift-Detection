"""Validate a patch against nodes of one cluster and roll it out node by node.

A node is not patched in place: merging a patch into the running config appends to lists, so an
edited patch would leave its old values behind. Instead every node gets its full desired config,
i.e. its role baseline with all of its patches (including the new version) applied, keeping the
node's own values wherever an ignore rule applies (hostname, addresses, ...). That config is
applied with `talosctl apply-config`, which also reverts any other drift on the node; the dry-run
diff shows exactly what changes.

Validation yields a plan: exactly which config goes to which nodes of which cluster, in which
mode. Applying only takes the plan id, so what runs is what was checked (and shown) beforehand.
Right before each node is changed, its live config must still be the one validated against,
and a second dry run must succeed. After each node the app checks that it now matches its baseline. Plans are kept in
memory and expire after PLAN_TTL seconds.
"""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from . import audit, auth, config, drift, notify, patches, scanner, sources, store, talos, vault
from .store import key

log = logging.getLogger("rollout")
MODES = ("no-reboot", "auto", "staged", "try")
PLAN_TTL = 15 * 60
SYNC_NAME = "(sync to baseline)"
READY_TIMEOUT = 600
READY_POLL = 5
REBOOT_GRACE = 10  # a rebooting node may still answer for a moment after the apply
HEALTH_TIMEOUT = 300
_plans: dict[str, dict] = {}
_runs: dict[str, dict] = {}


class RolloutError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def select_nodes(cid: str, target: str) -> list[dict]:
    """Nodes of the latest scan that a target covers: workers first, control planes last."""
    nodes = (store.latest(cid) or {}).get("nodes", [])
    if target == "all":
        hits = nodes
    elif target in patches.ROLES:
        hits = [n for n in nodes if n.get("role") == target]
    else:
        names = set(patches.target_nodes(target))
        hits = [n for n in nodes if {n["hostname"], n["address"]} & names]
        unknown = names - {n["hostname"] for n in hits} - {n["address"] for n in hits}
        if unknown:
            raise RolloutError(f"Not in the latest scan of this cluster: {', '.join(sorted(unknown))}")
    if not hits:
        raise RolloutError("No nodes match this target; run a scan first.")
    hits = sorted(hits, key=lambda n: (n.get("role") == "controlplane", n["hostname"]))
    return [{"address": n["address"], "hostname": n["hostname"], "role": n.get("role", "unknown")} for n in hits]


def _covered(cid: str, target: str) -> list[dict]:
    try:
        return select_nodes(cid, target)
    except RolloutError:
        return []


@contextmanager
def _cluster(cid: str):
    """This cluster's talosconfig as a file, and whether nodes are addressed directly."""
    tc_text = sources.load(cid, "talosconfig")
    if not tc_text:
        raise RolloutError("No talosconfig uploaded or linked for this cluster.")
    endpoints, _ = talos.context_nodes(tc_text.decode())
    with sources.materialize(cid, "talosconfig") as path:
        yield path, not endpoints


@contextmanager
def _temp_file(text: str):
    config.TMP_DIR.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="rollout-", suffix=".yaml", dir=config.TMP_DIR)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        yield path
    finally:
        os.unlink(path)


async def _baselines(cid: str, nodes: list[dict], data: bytes | None, target: str, patch_id: str | None,
                     name: str, drop: bool = False, position: int | None = None) -> dict[str, str]:
    """Each node's baseline with all its patches: the new or edited one included, the one being
    deleted (drop) left out, or the patches as they are (data None)."""
    v = vault.get()
    tmp_id = f"pending-{secrets.token_hex(4)}"
    entry = {"id": tmp_id, "name": name, "target": target}
    index = patches.all_patches(cid)
    if drop:
        index = [p for p in index if p["id"] != patch_id]
    elif data is not None:
        if patch_id:
            index = [entry if p["id"] == patch_id else p for p in index]
        else:
            index.insert(len(index) if position is None else min(position, len(index)), entry)
        v.save(key(cid, f"patch-{tmp_id}"), data)
    built: dict[tuple, str] = {}
    out = {}
    try:
        for n in nodes:
            if n["role"] not in patches.ROLES:
                raise RolloutError(f"{n['hostname']}: unknown role; scan again first")
            if not sources.exists(cid, n["role"]):
                raise RolloutError(f"No {n['role']}.yaml for this cluster; it is needed to build the node configs")
            applied = patches.applicable(n["role"], n["hostname"], n["address"], index)
            k = (n["role"], *(p["id"] for p in applied))
            if k not in built:
                try:
                    built[k] = await patches.build_baseline(cid, n["role"], applied)
                except talos.TalosError as e:
                    raise RolloutError(f"{n['hostname']}: {e}") from e
            out[n["address"]] = built[k]
    finally:
        v.delete(key(cid, f"patch-{tmp_id}"))
    return out


async def validate(cid: str, text: str, target: str, mode: str, patch_id: str | None = None,
                   name: str = "", path: str = "", sync: bool = False, delete: bool = False,
                   rollback_of: str | None = None, position: int | None = None, canary: bool = False,
                   skip_unreachable: bool = False) -> dict:
    """Build each node's desired config and dry-run it on every target node; returns a plan.

    With sync, no patch changes: the nodes are brought back to their baseline as it is.
    With delete, patch_id is removed: every node it applies to now gets its baseline without it.
    """
    cluster = store.get_cluster(cid)
    if not cluster:
        raise RolloutError("Cluster not found")
    if mode not in MODES:
        raise RolloutError(f"Unknown mode {mode}")
    opts = {"canary": canary, "skip_unreachable": skip_unreachable}
    if delete:
        return await _validate_delete(cid, cluster, patch_id, mode, rollback_of, **opts)
    if not patches.valid_target(target):
        raise RolloutError("Choose a valid target")
    data = None
    if not sync:
        data = text.replace("\r\n", "\n").encode()
        if len(data) > sources.MAX_SIZE:
            raise RolloutError("The patch is larger than 1 MB")
        error = patches.check_yaml(data)
        if error:
            raise RolloutError(error)

    base_sha, before, warnings = None, None, []
    nodes = select_nodes(cid, target)
    if sync:
        patch_id, name, path = None, SYNC_NAME, ""
    elif patch_id:
        existing = patches.get(cid, patch_id)
        if not existing:
            raise RolloutError("Patch not found")
        name, path = existing["name"], ""
        try:
            content = patches.read(cid, existing)
        except sources.SourceError as e:
            raise RolloutError(str(e)) from e
        base_sha, before = _sha(content), _before(cid, existing, content)
        _writable(cid, existing.get("path"), "write")
        # Nodes that have the patch now but fall outside the new target: they are rolled out too,
        # without the patch, so it is really removed from them instead of lingering as drift.
        selected = {n["address"] for n in nodes}
        left_out = [{**n, "removes": True} for n in _covered(cid, existing["target"]) if n["address"] not in selected]
        if left_out:
            warnings.append(
                f"The new target no longer includes {', '.join(n['hostname'] for n in left_out)}: "
                "this patch is removed from them as part of this rollout."
            )
            nodes = sorted(nodes + left_out, key=lambda n: (n["role"] == "controlplane", n["hostname"]))
    else:
        path = path.strip().strip("/")
        if path:
            try:
                sources.check_new_file(cid, path)
            except sources.SourceError as e:
                raise RolloutError(str(e)) from e
            _writable(cid, path, "create")
            name = path
        name = name.strip() or "patch.yaml"

    return await _dry_run_plan(cid, cluster, nodes, data, target, mode, patch_id, base_sha, name, path, warnings,
                               before=before, rollback_of=rollback_of, position=position, **opts)


def _rollback_target(cid: str, entry: dict, shas: dict | None = None) -> dict | None:
    """The patch a history entry is about, if it can still be rolled back; raises RolloutError why not.

    Only while the patch is still exactly as that rollout left it, so later changes are never
    overwritten unnoticed.
    """
    action = entry.get("action")
    if action in (None, "sync"):
        raise RolloutError("A sync cannot be rolled back: it only removed drift.")
    if not (entry["ok"] and entry.get("saved")):
        raise RolloutError("That rollout did not change the baseline, so there is nothing to roll back. "
                           "Use Sync nodes to baseline for nodes it left behind.")
    if action == "edit" and not entry.get("before"):
        raise RolloutError("No previous version was recorded for this edit (it predates rollback support).")
    p = patches.get(cid, entry["patch_id"]) if entry.get("patch_id") else next(
        (x for x in patches.all_patches(cid) if x["name"] == entry["patch"]), None)
    if action == "delete":
        if p or any(x["name"] == entry["patch"] for x in patches.all_patches(cid)):
            raise RolloutError(f"{entry['patch']} exists again, so this delete cannot be rolled back.")
        return None
    if not p:
        raise RolloutError(f"{entry['patch']} no longer exists; roll back its deletion first.")
    shas = {} if shas is None else shas
    if p["id"] not in shas:
        try:
            shas[p["id"]] = _sha(patches.read(cid, p))[:16]
        except sources.SourceError as e:
            raise RolloutError(str(e)) from e
    current = shas[p["id"]]
    if current != entry["sha256"] or p["target"] != entry.get("target_raw", p["target"]):
        raise RolloutError(f"{entry['patch']} changed after this rollout; roll back the newer change first.")
    return p


def rollback_blocker(cid: str, entry: dict, shas: dict | None = None) -> str | None:
    """Why a history entry cannot be rolled back (None: it can), for the history table.
    Pass one `shas` dict for a whole table, so each patch is read once."""
    try:
        _rollback_target(cid, entry, shas)
        return None
    except RolloutError as e:
        return str(e)


async def validate_rollback(cid: str, entry_id: str, mode: str, **opts) -> dict:
    """Plan that undoes one rollout from the history: a new patch is deleted again, an edit is
    reverted to the previous text and target, a deleted patch comes back."""
    entry = audit.get(cid, entry_id)
    if not entry:
        raise RolloutError("History entry not found")
    p = _rollback_target(cid, entry)
    if entry["action"] == "delete":
        before = entry["before"]
        return await validate(cid, before["text"], before["target"], mode, name=before["name"],
                              path=before["path"], rollback_of=entry_id, position=before.get("position"), **opts)
    if entry["action"] == "new":
        return await validate(cid, "", "", mode, patch_id=p["id"], delete=True, rollback_of=entry_id, **opts)
    return await validate(cid, entry["before"]["text"], entry["before"]["target"], mode, patch_id=p["id"],
                          rollback_of=entry_id, **opts)


def _writable(cid: str, rel: str | None, action: str) -> None:
    if rel:
        try:
            sources.check_writable(cid, rel, action)
        except sources.SourceError as e:
            raise RolloutError(str(e)) from e


def _inputs(cid: str) -> str:
    """Fingerprint of everything the node configs are built from: all patches (order, target,
    content) and the role baselines. A plan is only applied while this is unchanged."""
    parts = []
    for p in patches.all_patches(cid):
        try:
            parts.append([p["id"], p["target"], _sha(patches.read(cid, p))])
        except sources.SourceError:
            parts.append([p["id"], p["target"], "unreadable"])
    for role in patches.ROLES:
        try:
            data = sources.load(cid, role)
        except sources.SourceError:
            data = b"unreadable"
        parts.append([role, _sha(data) if data else None])
    return _sha(json.dumps(parts).encode())


def _before(cid: str, existing: dict, content: bytes) -> dict:
    """How a patch was before a change, so the change can be rolled back."""
    return {"name": existing["name"], "target": existing["target"], "path": existing.get("path") or "",
            "text": content.decode(errors="replace"), "position": patches.position(cid, existing["id"])}


async def _validate_delete(cid: str, cluster: dict, patch_id: str | None, mode: str, rollback_of: str | None = None,
                           **opts) -> dict:
    existing = patches.get(cid, patch_id) if patch_id else None
    if not existing:
        raise RolloutError("Patch not found")
    try:
        content = patches.read(cid, existing)
    except sources.SourceError as e:
        raise RolloutError(str(e)) from e
    _writable(cid, existing.get("path"), "delete")
    nodes = [{**n, "removes": True} for n in _covered(cid, existing["target"])]
    warnings = [] if nodes else ["No node in the latest scan gets this patch; it is only removed from the baseline."]
    if existing.get("path"):
        warnings.append(f"{existing['path']} is deleted from the base folder afterwards; its content stays in the history.")
    return await _dry_run_plan(cid, cluster, nodes, None, existing["target"], mode, patch_id, _sha(content),
                               existing["name"], "", warnings, delete=True, content=content,
                               before=_before(cid, existing, content), rollback_of=rollback_of, **opts)


async def _dry_run_plan(cid: str, cluster: dict, nodes: list[dict], data: bytes | None, target: str, mode: str,
                        patch_id: str | None, base_sha: str | None, name: str, path: str, warnings: list[str],
                        delete: bool = False, content: bytes | None = None, before: dict | None = None,
                        rollback_of: str | None = None, position: int | None = None, canary: bool = False,
                        skip_unreachable: bool = False) -> dict:
    inputs = _inputs(cid)
    skipped = []
    if skip_unreachable:
        down = {n["address"] for n in (store.latest(cid) or {}).get("nodes", []) if n.get("status") == "unreachable"}
        skipped = [n for n in nodes if n["address"] in down]
        nodes = [n for n in nodes if n["address"] not in down]
    baselines = await _baselines(cid, nodes, data, target, patch_id, name, drop=delete, position=position)
    ignore = store.settings(cid)["ignore"]
    try:
        with _cluster(cid) as (tc, direct):
            sem = asyncio.Semaphore(config.SCAN_CONCURRENCY)

            async def dry_run(n: dict) -> dict:
                async with sem:
                    try:
                        actual = await talos.machine_config(tc, n["address"], direct)
                        desired = drift.keep_ignored(baselines[n["address"]], actual, ignore)
                        with _temp_file(desired) as f:
                            out = await talos.apply_config(tc, n["address"], f, mode, direct, dry_run=True)
                        diff = drift.config_diff(actual, desired)
                        # Safety net: Talos sees changes that the masked diff does not show.
                        hidden = talos.dry_run_changes(out) if not diff else 0
                        return {**n, "removes": n.get("removes", False), "ok": True, "error": None,
                                "diff": diff, "summary": talos.dry_run_summary(out), "hidden_changes": hidden,
                                "desired": desired, "actual_sha": _sha(actual.encode())}
                    except talos.TalosError as e:
                        return {**n, "removes": n.get("removes", False), "ok": False, "diff": "", "error": str(e),
                                "summary": "", "hidden_changes": 0, "desired": None}

            results = list(await asyncio.gather(*(dry_run(n) for n in nodes)))
    except sources.SourceError as e:
        raise RolloutError(str(e)) from e
    if skip_unreachable:
        skipped += [r for r in results if not r["ok"] and _unreachable(r["error"])]
        results = [r for r in results if r["ok"] or not _unreachable(r["error"])]
    if skipped:
        if not results:
            raise RolloutError("All selected nodes are unreachable; nothing to apply.")
        warnings.append(f"Skipped because unreachable: {', '.join(n['hostname'] for n in skipped)}. They do not get "
                        "this change and will show drift; use Sync nodes to baseline once they are back.")

    ok = all(r["ok"] for r in results)
    plan_id = None
    if ok:
        _prune()
        plan_id = secrets.token_urlsafe(12)
        _plans[plan_id] = {
            "cid": cid, "expires": time.monotonic() + PLAN_TTL, "data": data, "target": target,
            "mode": mode, "patch_id": patch_id, "base_sha": base_sha, "name": name, "path": path,
            "ignore": ignore, "nodes": results, "delete": delete, "content": content, "before": before,
            "rollback_of": rollback_of, "position": position, "inputs": inputs, "canary": canary,
        }
    return {
        "plan_id": plan_id, "ok": ok, "cluster": cluster["name"], "mode": mode, "warnings": warnings, "delete": delete,
        "rollback_of": rollback_of, "canary": canary,
        "skipped": [{k: n.get(k) for k in ("address", "hostname", "role")} for n in skipped],
        "target_label": patches.target_label(target), "name": name,
        "nodes": [{k: r[k] for k in ("address", "hostname", "role", "removes", "ok", "diff", "summary", "hidden_changes", "error")}
                  for r in results],
    }


UNREACHABLE = ("connection refused", "unavailable", "deadline exceeded", "timed out", "no route to host",
               "connection reset", "i/o timeout", "network is unreachable")


def _unreachable(error: str | None) -> bool:
    return bool(error) and any(s in error.lower() for s in UNREACHABLE)


def _summary(plan: dict, state: dict) -> dict:
    """Activity log details of a rollout (no patch text: that is in the cluster's patch history)."""
    out = {"what": state["action"], "patch": plan["name"], "target": state["target_label"], "mode": plan["mode"],
           "sha256": _sha(_text(plan))[:16], "nodes": [n["hostname"] for n in state["nodes"]]}
    if plan["rollback_of"]:
        out["rollback_of"] = plan["rollback_of"]
    return out


def _action(plan: dict) -> str:
    if plan["delete"]:
        return "delete"
    if plan["data"] is None:
        return "sync"
    return "edit" if plan["patch_id"] else "new"


def _text(plan: dict) -> bytes:
    """The patch text a rollout was about: the new version, or the one deleted."""
    return plan["content"] if plan["delete"] else plan["data"] or b""


def _prune() -> None:
    now = time.monotonic()
    for pid in [pid for pid, p in _plans.items() if p["expires"] < now]:
        del _plans[pid]


ACTIVE = ("checking", "applying", "waiting", "health", "verifying")
INTERRUPTED = ("Interrupted: the app restarted during this rollout. Nodes marked 'interrupted' may or may not "
               "have the new config; check them and use Sync nodes to baseline.")
_decisions: dict[str, asyncio.Future] = {}


def is_running(cid: str) -> bool:
    return bool((status(cid) or {}).get("running"))


def status(cid: str) -> dict | None:
    """The cluster's current or last rollout (kept in the vault, so it survives a restart)."""
    if cid not in _runs:
        data = vault.get().load(key(cid, "rollout"))
        if data:
            _runs[cid] = json.loads(data)
    return _runs.get(cid)


def _persist(cid: str, state: dict) -> None:
    vault.get().save(key(cid, "rollout"), json.dumps(state).encode())


def start(cid: str, plan_id: str, actor: dict | str) -> dict:
    """Start rolling out a validated plan; raises RolloutError if it may not run (any more)."""
    _prune()
    plan = _plans.get(plan_id)
    if not plan:
        raise RolloutError("This validation has expired or was already used; validate again.")
    if plan["cid"] != cid:
        raise RolloutError("This validation belongs to another cluster.")
    if is_running(cid):
        raise RolloutError("A rollout is already running for this cluster.")
    if plan["patch_id"]:
        existing = patches.get(cid, plan["patch_id"])
        try:
            current = _sha(patches.read(cid, existing)) if existing else None
        except sources.SourceError:
            current = None
        if current != plan["base_sha"]:
            raise RolloutError("The patch was changed since it was validated; validate again.")
    if _inputs(cid) != plan["inputs"]:
        raise RolloutError("Patches or baseline files of this cluster changed since validation; validate again.")
    del _plans[plan_id]
    if isinstance(actor, str):
        actor = {"id": actor, "username": actor, "name": actor, "method": "", "ip": ""}
    state = {
        "running": True, "paused": False, "started": _now(), "finished": None, "user": auth.actor_label(actor),
        "actor": actor, "name": plan["name"], "mode": plan["mode"], "target_label": patches.target_label(plan["target"]),
        "ok": None, "saved": False, "error": None, "action": _action(plan), "patch_id": plan["patch_id"],
        "rollback_of": plan["rollback_of"], "canary": plan["canary"], "sha256": _sha(_text(plan))[:16],
        "nodes": [{k: n[k] for k in ("address", "hostname", "role", "removes")} | {"status": "pending", "error": None}
                  for n in plan["nodes"]],
    }
    _runs[cid] = state
    _persist(cid, state)
    audit.record(actor, "rollout.start", store.get_cluster(cid), **_summary(plan, state))
    asyncio.create_task(_run(cid, plan, state))
    return state


def decide(cid: str, go: bool, actor: dict) -> dict:
    """Continue or stop a rollout that is paused after its first node (canary)."""
    fut = _decisions.get(cid)
    state = status(cid)
    if not fut or fut.done() or not state:
        raise RolloutError("No rollout of this cluster is waiting for a decision.")
    if not go:
        state["error"] = f"Stopped after the first node by {auth.actor_label(actor)}."
    audit.record(actor, "rollout.continue" if go else "rollout.stop", store.get_cluster(cid),
                 patch=state["name"], done=[n["hostname"] for n in state["nodes"] if n["status"] == "done"])
    fut.set_result(go)
    return state


def recover() -> None:
    """At startup: a rollout that was still running when the app stopped is marked interrupted."""
    for c in store.clusters():
        state = status(c["id"])
        if not state or not state.get("running"):
            continue
        for n in state["nodes"]:
            if n["status"] == "pending":
                n["status"] = "skipped"
            elif n["status"] in ACTIVE:
                n["status"], n["error"] = "interrupted", "the app restarted while this node was being changed"
        state.update(running=False, paused=False, ok=False, finished=_now(), error=INTERRUPTED)
        _persist(c["id"], state)
        nodes = [{k: n.get(k) for k in ("hostname", "address", "removes", "status", "error")} for n in state["nodes"]]
        audit.add(c["id"], {
            "id": secrets.token_hex(6), "time": state["started"], "user": state["user"], "actor": state["actor"],
            "patch": state["name"], "action": state["action"], "patch_id": state["patch_id"],
            "target": state["target_label"], "mode": state["mode"], "sha256": state.get("sha256", ""), "text": "",
            "rollback_of": state.get("rollback_of"), "ok": False, "saved": False, "error": INTERRUPTED, "nodes": nodes,
        })
        audit.record(state["actor"], "rollout.interrupted", c, patch=state["name"],
                     results={n["hostname"]: n["status"] for n in state["nodes"]})
        notify.send("rollout.interrupted", c, f"Rollout of {state['name']} on {c['name']} was interrupted by a restart.",
                    patch=state["name"], user=state["user"])
        log.warning("rollout of %s on %s was interrupted by a restart", state["name"], c["id"])


async def _wait_ready(tc: str, address: str, direct: bool, mode: str) -> bool:
    if mode in ("auto", "try"):
        await asyncio.sleep(REBOOT_GRACE)
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline:
        if await talos.node_ready(tc, address, direct):
            return True
        await asyncio.sleep(READY_POLL)
    return False


async def _wait_healthy(tc: str, n: dict, direct: bool) -> None:
    """Before the next node: etcd healthy on a control plane, and the Kubernetes node Ready
    (when Talos reports it). Raises TalosError on timeout."""
    deadline = time.monotonic() + HEALTH_TIMEOUT
    while True:
        etcd_ok = n["role"] != "controlplane" or await talos.etcd_healthy(tc, n["address"], direct)
        k8s = await talos.kubernetes_node_ready(tc, n["address"], n["hostname"], direct)
        if etcd_ok and k8s is not False:
            return
        if time.monotonic() >= deadline:
            what = "etcd is not healthy" if not etcd_ok else "the Kubernetes node is not Ready"
            raise talos.TalosError(f"{what} after {HEALTH_TIMEOUT // 60} minutes; stopped before the next node")
        await asyncio.sleep(READY_POLL)


async def _apply_node(tc: str, direct: bool, n: dict, planned: dict, mode: str, ignore: list[str], changed) -> None:
    """Check, dry run, apply, wait, check health, verify one node; raises TalosError on the first problem."""
    def step(s: str) -> None:
        n["status"] = s
        changed()

    step("checking")
    current = await talos.machine_config(tc, n["address"], direct)
    if _sha(current.encode()) != planned["actual_sha"]:
        raise talos.TalosError("the node's config changed since validation; validate again")
    with _temp_file(planned["desired"]) as f:
        await talos.apply_config(tc, n["address"], f, mode, direct, dry_run=True)
        step("applying")
        await talos.apply_config(tc, n["address"], f, mode, direct)
    step("waiting")
    if not await _wait_ready(tc, n["address"], direct, mode):
        raise talos.TalosError(f"not ready after {READY_TIMEOUT // 60} minutes")
    step("health")
    await _wait_healthy(tc, n, direct)
    if mode == "staged":
        return  # only active after the next reboot
    step("verifying")
    actual = await talos.machine_config(tc, n["address"], direct)
    left = drift.compute(planned["desired"], actual, ignore)["changes"]
    if left:
        paths = ", ".join(c["path"] for c in left[:5]) + (" …" if len(left) > 5 else "")
        raise talos.TalosError(f"applied, but the node still differs from its baseline at: {paths}")


async def _canary_pause(cid: str, state: dict) -> bool:
    """Wait for Continue/Stop after the first node; True means go on."""
    fut = asyncio.get_running_loop().create_future()
    _decisions[cid] = fut
    state["paused"] = True
    _persist(cid, state)
    notify.send("rollout.paused", store.get_cluster(cid),
                f"Rollout of {state['name']} paused after the first node; waiting for Continue or Stop.",
                patch=state["name"], user=state["user"])
    try:
        return await fut
    finally:
        _decisions.pop(cid, None)
        state["paused"] = False
        _persist(cid, state)


def _save_result(cid: str, plan: dict, state: dict) -> None:
    """After a successful rollout: the baseline follows (patch saved, deleted or restored)."""
    if plan["mode"] == "try":
        return  # reverted by Talos after its timeout, so it never becomes part of the baseline
    if plan["delete"]:
        linked = (patches.get(cid, plan["patch_id"]) or {}).get("path")
        patches.delete(cid, plan["patch_id"])
        state["saved"] = True
        if linked:
            try:
                sources.delete_file(cid, linked)
            except sources.SourceError as e:
                state["error"] = f"Removed from the nodes and the baseline, but the file was not deleted: {e}"
    elif plan["data"] is not None:
        try:
            state["patch_id"] = patches.save(cid, plan["patch_id"], plan["data"], plan["target"], plan["name"],
                                             plan["path"])["id"]
            if plan["position"] is not None:
                patches.place(cid, state["patch_id"], plan["position"])
            state["saved"] = True
        except sources.SourceError as e:
            state["error"] = f"Applied to all nodes, but saving the patch failed: {e}"


async def _run(cid: str, plan: dict, state: dict) -> None:
    planned = {n["address"]: n for n in plan["nodes"]}
    ok = False
    try:
        with _cluster(cid) as (tc, direct):
            for i, n in enumerate(state["nodes"]):
                if i == 1 and plan["canary"] and not await _canary_pause(cid, state):
                    break
                try:
                    await _apply_node(tc, direct, n, planned[n["address"]], plan["mode"], plan["ignore"],
                                      lambda: _persist(cid, state))
                    n["status"] = "done"
                except talos.TalosError as e:
                    n["status"], n["error"] = "failed", str(e)
                    break
                finally:
                    _persist(cid, state)
    except (RolloutError, sources.SourceError) as e:
        state["error"] = str(e)
    except Exception:
        log.exception("rollout on %s failed", cid)
        state["error"] = "Unexpected error, see the container logs."
    try:
        for n in state["nodes"]:
            if n["status"] == "pending":
                n["status"] = "skipped"
        ok = state["error"] is None and all(n["status"] == "done" for n in state["nodes"])
        if ok:
            _save_result(cid, plan, state)
    except Exception:
        log.exception("saving the result of the rollout on %s failed", cid)
        state["error"] = state["error"] or "Applied, but saving the result failed; see the container logs."
    finally:
        # Never leave the cluster locked, whatever went wrong above.
        state.update(running=False, paused=False, finished=_now(), ok=ok)
        _persist(cid, state)
    try:
        cluster = store.get_cluster(cid)
        if cluster:
            audit.add(cid, {
                "time": state["started"], "user": state["user"], "patch": plan["name"],
                "id": secrets.token_hex(6), "actor": state["actor"], "action": state["action"],
                "patch_id": state["patch_id"], "target_raw": plan["target"], "before": plan["before"],
                "rollback_of": plan["rollback_of"], "sha256": _sha(_text(plan))[:16],
                "text": _text(plan).decode(errors="replace"), "target": state["target_label"], "mode": plan["mode"],
                "ok": ok, "saved": state["saved"], "error": state["error"],
                "nodes": [{k: n[k] for k in ("hostname", "address", "removes", "status", "error")} for n in state["nodes"]],
            })
            audit.record(state["actor"], "rollout.finish", cluster, **_summary(plan, state), ok=ok,
                         saved=state["saved"], error=state["error"],
                         results={n["hostname"]: n["status"] for n in state["nodes"]})
            verdict = "succeeded" if ok else "FAILED"
            notify.send("rollout.finished" if ok else "rollout.failed", cluster,
                        f"Rollout of {plan['name']} on {cluster['name']} {verdict} ({state['user']})."
                        + (f" {state['error']}" if state["error"] else ""),
                        patch=plan["name"], user=state["user"], ok=ok,
                        results={n["hostname"]: n["status"] for n in state["nodes"]})
            scanner.request(cid)
    except Exception:
        log.exception("recording the rollout on %s failed", cid)
    log.info("rollout of %s on %s finished: ok=%s", plan["name"], cid, ok)
