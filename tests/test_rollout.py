import asyncio

import pytest
import yaml

from app import audit, patches, rollout, scanner, sources, store, talos, vault
from app.vault import Vault

TALOSCONFIG = b"context: c\ncontexts:\n  c:\n    endpoints: [10.0.0.1]\n"
PATCH = "machine:\n  sysctls:\n    a: '1'\n"
NODES = [
    ("10.0.0.1", "cp-1", "controlplane"),
    ("10.0.0.2", "cp-2", "controlplane"),
    ("10.0.1.1", "w-1", "worker"),
    ("10.0.1.2", "w-2", "worker"),
]


def _merge(base, patch):
    if isinstance(base, dict) and isinstance(patch, dict):
        return {**base, **{k: _merge(base.get(k), v) for k, v in patch.items()}}
    return patch


def _config(role, hostname, extra=None):
    doc = {"version": "v1alpha1", "machine": {"type": role, "network": {"hostname": hostname}}}
    return yaml.safe_dump(_merge(doc, extra or {}))


@pytest.fixture
def cluster(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "_vault", Vault("x" * 40, tmp_path / "data", tmp_path / "tmp"))
    monkeypatch.setattr(rollout.config, "TMP_DIR", tmp_path / "tmp")
    monkeypatch.setattr(rollout, "READY_POLL", 0)
    monkeypatch.setattr(rollout, "REBOOT_GRACE", 0)
    monkeypatch.setattr(scanner, "request", lambda cid: None)
    rollout._plans.clear()
    rollout._runs.clear()
    rollout._decisions.clear()
    c = store.add_cluster("prod")
    sources.save_upload(c["id"], "talosconfig", TALOSCONFIG)
    for role in patches.ROLES:
        sources.save_upload(c["id"], role, f"version: v1alpha1\nmachine:\n  type: {role}\n".encode())
    nodes = [{"address": a, "hostname": h, "role": r, "status": "in-sync"} for a, h, r in NODES]
    store.add_scan(c["id"], {"finished_at": "2026-01-01T00:00:00+00:00", "nodes": nodes})
    return c["id"]


@pytest.fixture
def fake(monkeypatch):
    """A tiny Talos: a config per node; apply-config replaces it, patches merge maps."""
    state = {
        "configs": {a: _config(r, h) for a, h, r in NODES},
        "applied": [], "fail": set(), "dry_fail": set(), "noop": set(), "etcd_down": set(), "k8s": {},
    }

    async def patch_config(base_path, patch_paths):
        doc = yaml.safe_load(open(base_path))
        for p in patch_paths:
            doc = _merge(doc, yaml.safe_load(open(p)))
        return yaml.safe_dump(doc)

    async def machine_config(tc, node, direct=False):
        return state["configs"][node]

    async def apply_config(tc, node, path, mode, direct=False, dry_run=False):
        desired = open(path).read()
        if dry_run:
            if node in state["dry_fail"]:
                raise talos.TalosError("connection refused")
            same = yaml.safe_load(desired) == yaml.safe_load(state["configs"][node])
            return "" if same else f"Dry run summary:\n--- a\n+++ b\n-{yaml.safe_load(state['configs'][node])}\n+{yaml.safe_load(desired)}\n"
        state["applied"].append((node, mode))
        if node in state["fail"]:
            raise talos.TalosError("boom")
        if node not in state["noop"]:
            state["configs"][node] = desired
        return ""

    async def node_ready(tc, node, direct=False):
        return True

    async def etcd_healthy(tc, node, direct=False):
        return node not in state["etcd_down"]

    async def kubernetes_node_ready(tc, node, hostname, direct=False):
        return state["k8s"].get(node)

    monkeypatch.setattr(talos, "patch_config", patch_config)
    monkeypatch.setattr(talos, "machine_config", machine_config)
    monkeypatch.setattr(talos, "apply_config", apply_config)
    monkeypatch.setattr(talos, "node_ready", node_ready)
    monkeypatch.setattr(talos, "etcd_healthy", etcd_healthy)
    monkeypatch.setattr(talos, "kubernetes_node_ready", kubernetes_node_ready)
    monkeypatch.setattr(rollout, "HEALTH_TIMEOUT", 0)
    return state


async def _finish(cid):
    while rollout.is_running(cid):
        await asyncio.sleep(0)


def _rollout(cid, *args, **kw):
    async def go():
        plan = await rollout.validate(cid, *args, **kw)
        assert plan["ok"], plan
        rollout.start(cid, plan["plan_id"], "admin")
        await _finish(cid)
        return plan

    return asyncio.run(go())


def test_select_nodes_order_and_unknown(cluster):
    assert [n["hostname"] for n in rollout.select_nodes(cluster, "all")] == ["w-1", "w-2", "cp-1", "cp-2"]
    assert [n["hostname"] for n in rollout.select_nodes(cluster, "controlplane")] == ["cp-1", "cp-2"]
    assert [n["hostname"] for n in rollout.select_nodes(cluster, "nodes:cp-2,10.0.1.1")] == ["w-1", "cp-2"]
    with pytest.raises(rollout.RolloutError, match="w-9"):
        rollout.select_nodes(cluster, "nodes:w-1,w-9")


def test_new_patch_reaches_nodes_and_is_saved(cluster, fake):
    plan = _rollout(cluster, PATCH, "nodes:w-1,cp-1", "no-reboot", name="sysctls.yaml")
    assert plan["cluster"] == "prod" and all(n["diff"] for n in plan["nodes"])
    assert fake["applied"] == [("10.0.1.1", "no-reboot"), ("10.0.0.1", "no-reboot")]
    assert yaml.safe_load(fake["configs"]["10.0.1.1"])["machine"]["sysctls"] == {"a": "1"}
    assert "sysctls" not in yaml.safe_load(fake["configs"]["10.0.1.2"])["machine"]
    state = rollout.status(cluster)
    assert state["ok"] and state["saved"]
    saved = patches.all_patches(cluster)
    assert [(p["name"], p["target"]) for p in saved] == [("sysctls.yaml", "nodes:w-1,cp-1")]
    entry = audit.entries(cluster)[0]
    assert entry["user"] == "admin" and entry["ok"] and [n["status"] for n in entry["nodes"]] == ["done", "done"]


def test_editing_a_list_replaces_it_and_keeps_ignored_values(cluster, fake):
    """The registry-mirror case: an edited endpoint list must not keep the old entry."""
    mirrors = lambda url: {"machine": {"registries": {"mirrors": {"docker.io": {"endpoints": [url]}}}}}
    old = patches.add(cluster, "mirrors.yaml", yaml.safe_dump(mirrors("https://old")).encode(), "node:w-1")
    fake["configs"]["10.0.1.1"] = _config("worker", "w-1", mirrors("https://old"))
    _rollout(cluster, yaml.safe_dump(mirrors("https://new")), "node:w-1", "no-reboot", patch_id=old["id"])
    live = yaml.safe_load(fake["configs"]["10.0.1.1"])
    assert live["machine"]["registries"]["mirrors"]["docker.io"]["endpoints"] == ["https://new"]
    assert live["machine"]["network"]["hostname"] == "w-1"  # ignored path: the node keeps its own value
    assert rollout.status(cluster)["ok"]


def test_other_drift_on_the_node_is_reverted(cluster, fake):
    fake["configs"]["10.0.1.1"] = _config("worker", "w-1", {"machine": {"kubelet": {"extraArgs": {"x": "1"}}}})
    plan = _rollout(cluster, PATCH, "node:w-1", "no-reboot", name="p.yaml")
    assert plan["nodes"][0]["diff"]
    assert "kubelet" not in yaml.safe_load(fake["configs"]["10.0.1.1"])["machine"]


def test_stops_at_first_failure_and_does_not_save(cluster, fake):
    fake["fail"].add("10.0.1.2")
    _rollout(cluster, PATCH, "all", "auto", name="p.yaml")
    assert [n for n, _ in fake["applied"]] == ["10.0.1.1", "10.0.1.2"]
    state = rollout.status(cluster)
    assert [n["status"] for n in state["nodes"]] == ["done", "failed", "skipped", "skipped"]
    assert not state["ok"] and not state["saved"]
    assert patches.all_patches(cluster) == []
    assert not audit.entries(cluster)[0]["ok"]


def test_node_changed_after_validation_is_not_applied(cluster, fake):
    async def go():
        plan = await rollout.validate(cluster, PATCH, "node:w-1", "no-reboot", name="p.yaml")
        fake["configs"]["10.0.1.1"] = _config("worker", "w-1", {"machine": {"sysctls": {"b": "2"}}})
        rollout.start(cluster, plan["plan_id"], "admin")
        await _finish(cluster)

    asyncio.run(go())
    assert fake["applied"] == []
    node = rollout.status(cluster)["nodes"][0]
    assert node["status"] == "failed" and "changed since validation" in node["error"]


def test_node_that_does_not_match_baseline_afterwards_fails(cluster, fake):
    fake["noop"].add("10.0.1.1")
    _rollout(cluster, PATCH, "node:w-1", "no-reboot", name="p.yaml")
    node = rollout.status(cluster)["nodes"][0]
    assert node["status"] == "failed" and "machine.sysctls.a" in node["error"]
    assert patches.all_patches(cluster) == []


def test_failed_dry_run_gives_no_plan(cluster, fake):
    fake["dry_fail"].add("10.0.1.2")
    plan = asyncio.run(rollout.validate(cluster, PATCH, "worker", "no-reboot"))
    assert not plan["ok"] and plan["plan_id"] is None
    assert [n["error"] for n in plan["nodes"]] == [None, "connection refused"]


def test_plan_is_bound_to_cluster_and_single_use(cluster, fake):
    other = store.add_cluster("lab")["id"]

    async def go():
        plan = await rollout.validate(cluster, PATCH, "worker", "no-reboot")
        with pytest.raises(rollout.RolloutError, match="another cluster"):
            rollout.start(other, plan["plan_id"], "admin")
        rollout.start(cluster, plan["plan_id"], "admin")
        await _finish(cluster)
        with pytest.raises(rollout.RolloutError, match="expired or was already used"):
            rollout.start(cluster, plan["plan_id"], "admin")

    asyncio.run(go())


def test_edit_refused_when_changed_meanwhile(cluster, fake):
    p = patches.add(cluster, "old.yaml", b"machine: {}\n", "worker")

    async def go():
        plan = await rollout.validate(cluster, PATCH, "worker", "no-reboot", patch_id=p["id"])
        patches.save(cluster, p["id"], b"machine: {sysctls: {b: '2'}}\n", "worker")
        with pytest.raises(rollout.RolloutError, match="changed since"):
            rollout.start(cluster, plan["plan_id"], "admin")

    asyncio.run(go())


def test_try_mode_is_not_saved(cluster, fake):
    _rollout(cluster, PATCH, "worker", "try", name="t.yaml")
    assert rollout.status(cluster)["ok"] and not rollout.status(cluster)["saved"]
    assert patches.all_patches(cluster) == []


def test_validate_rejects_bad_input(cluster, fake):
    for args, match in [
        ((cluster, "machine: [", "all", "no-reboot"), "Invalid YAML"),
        ((cluster, PATCH, "all", "reboot-now"), "Unknown mode"),
        ((cluster, PATCH, "nodes:", "no-reboot"), "valid target"),
        (("nope", PATCH, "all", "no-reboot"), "Cluster not found"),
    ]:
        with pytest.raises(rollout.RolloutError, match=match):
            asyncio.run(rollout.validate(*args))


def test_target_of_an_existing_patch_is_locked(cluster, fake):
    """Narrowing (or otherwise changing) the target would silently remove the patch from nodes."""
    _rollout(cluster, PATCH, "worker", "no-reboot", name="sysctls.yaml")
    p = patches.all_patches(cluster)[0]
    fake["applied"].clear()
    for target in ("node:w-1", "all", "controlplane"):
        with pytest.raises(rollout.RolloutError, match="cannot be changed"):
            asyncio.run(rollout.validate(cluster, PATCH, target, "no-reboot", patch_id=p["id"]))
    assert fake["applied"] == [] and patches.get(cluster, p["id"])["target"] == "worker"
    assert all(_sysctls(fake, a) == {"a": "1"} for a in ("10.0.1.1", "10.0.1.2"))


def test_sync_brings_a_drifting_node_back_to_its_baseline(cluster, fake):
    p = patches.add(cluster, "sysctls.yaml", PATCH.encode(), "node:w-1")
    fake["configs"]["10.0.1.2"] = _config("worker", "w-2", yaml.safe_load(PATCH))  # left over: drift
    plan = _rollout(cluster, "", "node:w-2", "no-reboot", sync=True)
    assert plan["name"] == rollout.SYNC_NAME and plan["nodes"][0]["diff"]
    assert "sysctls" not in yaml.safe_load(fake["configs"]["10.0.1.2"])["machine"]
    state = rollout.status(cluster)
    assert state["ok"] and not state["saved"]
    assert patches.all_patches(cluster) == [p]  # patches untouched
    assert audit.entries(cluster)[0]["patch"] == rollout.SYNC_NAME


def _with_patch_on_workers(cluster, fake):
    _rollout(cluster, PATCH, "worker", "no-reboot", name="sysctls.yaml")
    return patches.all_patches(cluster)[0]


def test_delete_removes_the_patch_from_nodes_then_from_the_baseline(cluster, fake):
    p = _with_patch_on_workers(cluster, fake)
    plan = _rollout(cluster, "", "", "no-reboot", patch_id=p["id"], delete=True)
    assert plan["delete"] and [n["hostname"] for n in plan["nodes"]] == ["w-1", "w-2"]
    assert all("sysctls" not in yaml.safe_load(fake["configs"][a])["machine"] for a in ("10.0.1.1", "10.0.1.2"))
    assert patches.all_patches(cluster) == []
    entry = audit.entries(cluster)[0]
    assert entry["action"] == "delete" and entry["text"] == PATCH and entry["ok"]


def test_failed_delete_keeps_the_patch(cluster, fake):
    p = _with_patch_on_workers(cluster, fake)
    fake["fail"].add("10.0.1.2")
    _rollout(cluster, "", "", "no-reboot", patch_id=p["id"], delete=True)
    assert [n["status"] for n in rollout.status(cluster)["nodes"]] == ["done", "failed"]
    assert patches.get(cluster, p["id"])  # still in the baseline; w-1 shows drift until fixed


def test_delete_refused_when_patch_changed_meanwhile(cluster, fake):
    p = _with_patch_on_workers(cluster, fake)

    async def go():
        plan = await rollout.validate(cluster, "", "", "no-reboot", patch_id=p["id"], delete=True)
        patches.save(cluster, p["id"], b"machine: {sysctls: {b: '2'}}\n", "worker")
        with pytest.raises(rollout.RolloutError, match="changed since"):
            rollout.start(cluster, plan["plan_id"], "admin")

    asyncio.run(go())


def test_delete_of_a_patch_no_node_gets(cluster, fake):
    p = patches.add(cluster, "gone.yaml", PATCH.encode(), "node:old-node")
    plan = _rollout(cluster, "", "", "no-reboot", patch_id=p["id"], delete=True)
    assert plan["nodes"] == [] and plan["warnings"]
    assert patches.all_patches(cluster) == []


def test_try_delete_keeps_the_patch(cluster, fake):
    p = _with_patch_on_workers(cluster, fake)
    _rollout(cluster, "", "", "try", patch_id=p["id"], delete=True)
    assert patches.get(cluster, p["id"])


def test_delete_removes_a_linked_patch_file(cluster, fake, tmp_path, monkeypatch):
    base = tmp_path / "cfg" / "clus"
    (base / "patch").mkdir(parents=True)
    (base / "patch" / "s.yaml").write_text(PATCH)
    monkeypatch.setattr(sources.config, "CONFIG_DIR", tmp_path / "cfg")
    sources.set_base_dir(cluster, "clus")
    p = patches.add_link(cluster, "patch/s.yaml", "worker")
    _rollout(cluster, "", "", "no-reboot", patch_id=p["id"], delete=True)
    assert rollout.status(cluster)["ok"] and rollout.status(cluster)["error"] is None
    assert not (base / "patch" / "s.yaml").exists() and patches.all_patches(cluster) == []
    assert audit.entries(cluster)[0]["text"] == PATCH


def _rollback(cid, entry, mode="no-reboot"):
    async def go():
        plan = await rollout.validate_rollback(cid, entry["id"], mode)
        assert plan["ok"] and plan["rollback_of"] == entry["id"], plan
        rollout.start(cid, plan["plan_id"], "admin")
        await _finish(cid)
        return plan

    return asyncio.run(go())


def _sysctls(fake, address):
    return yaml.safe_load(fake["configs"][address])["machine"].get("sysctls")


def test_rollback_of_a_new_patch_deletes_it(cluster, fake):
    _rollout(cluster, PATCH, "worker", "no-reboot", name="s.yaml")
    _rollback(cluster, audit.entries(cluster)[0])
    assert patches.all_patches(cluster) == [] and _sysctls(fake, "10.0.1.1") is None
    assert audit.entries(cluster)[0]["rollback_of"] and audit.entries(cluster)[0]["action"] == "delete"


def test_rollback_of_an_edit_restores_the_text(cluster, fake):
    _rollout(cluster, PATCH, "worker", "no-reboot", name="s.yaml")
    p = patches.all_patches(cluster)[0]
    _rollout(cluster, "machine:\n  sysctls:\n    a: '9'\n", "worker", "no-reboot", patch_id=p["id"])
    assert _sysctls(fake, "10.0.1.1") == {"a": "9"}
    _rollback(cluster, audit.entries(cluster)[0])
    p = patches.get(cluster, p["id"])
    assert p["target"] == "worker" and patches.read(cluster, p) == PATCH.encode()
    assert _sysctls(fake, "10.0.1.1") == {"a": "1"} and _sysctls(fake, "10.0.1.2") == {"a": "1"}


def test_rollback_of_a_delete_restores_patch_and_position(cluster, fake):
    _rollout(cluster, PATCH, "worker", "no-reboot", name="first.yaml")
    _rollout(cluster, "machine:\n  sysctls:\n    b: '2'\n", "worker", "no-reboot", name="second.yaml")
    first = patches.all_patches(cluster)[0]
    _rollout(cluster, "", "", "no-reboot", patch_id=first["id"], delete=True)
    assert [p["name"] for p in patches.all_patches(cluster)] == ["second.yaml"]
    _rollback(cluster, audit.entries(cluster)[0])
    assert [(p["name"], p["target"]) for p in patches.all_patches(cluster)] == [("first.yaml", "worker"), ("second.yaml", "worker")]
    assert _sysctls(fake, "10.0.1.2") == {"a": "1", "b": "2"}


def test_rollback_refused_when_patch_changed_later(cluster, fake):
    _rollout(cluster, PATCH, "worker", "no-reboot", name="s.yaml")
    p = patches.all_patches(cluster)[0]
    _rollout(cluster, "machine:\n  sysctls:\n    a: '2'\n", "worker", "no-reboot", patch_id=p["id"])
    new_entry = audit.entries(cluster)[1]  # the original "new"
    with pytest.raises(rollout.RolloutError, match="changed after this rollout"):
        asyncio.run(rollout.validate_rollback(cluster, new_entry["id"], "no-reboot"))


def test_rollback_of_rollback_and_unsupported_cases(cluster, fake):
    _rollout(cluster, PATCH, "worker", "no-reboot", name="s.yaml")
    _rollback(cluster, audit.entries(cluster)[0])  # deletes it
    _rollback(cluster, audit.entries(cluster)[0])  # and back again
    assert [p["name"] for p in patches.all_patches(cluster)] == ["s.yaml"]
    _rollout(cluster, "", "node:w-1", "no-reboot", sync=True)
    with pytest.raises(rollout.RolloutError, match="sync cannot"):
        asyncio.run(rollout.validate_rollback(cluster, audit.entries(cluster)[0]["id"], "no-reboot"))
    fake["fail"].add("10.0.1.1")
    p = patches.all_patches(cluster)[0]
    _rollout(cluster, "machine:\n  sysctls:\n    a: '3'\n", "worker", "no-reboot", patch_id=p["id"])
    with pytest.raises(rollout.RolloutError, match="nothing to roll back"):
        asyncio.run(rollout.validate_rollback(cluster, audit.entries(cluster)[0]["id"], "no-reboot"))


def test_rollback_blocker_explains_why_not(cluster, fake):
    _rollout(cluster, PATCH, "worker", "no-reboot", name="s.yaml")
    new = audit.entries(cluster)[0]
    assert rollout.rollback_blocker(cluster, new) is None
    _rollback(cluster, new)
    _rollback(cluster, audit.entries(cluster)[0])  # the patch is back
    delete_entry = audit.entries(cluster)[1]
    assert "exists again" in rollout.rollback_blocker(cluster, delete_entry)


async def _until(pred):
    for _ in range(10000):
        if pred():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


def test_plan_refused_when_another_patch_changed(cluster, fake):
    async def go():
        plan = await rollout.validate(cluster, PATCH, "worker", "no-reboot", name="a.yaml")
        patches.add(cluster, "other.yaml", b"machine: {sysctls: {z: '1'}}\n", "all")
        with pytest.raises(rollout.RolloutError, match="changed since validation"):
            rollout.start(cluster, plan["plan_id"], "admin")

    asyncio.run(go())


def test_failure_while_saving_never_leaves_the_cluster_locked(cluster, fake, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(patches, "save", boom)
    _rollout(cluster, PATCH, "node:w-1", "no-reboot", name="a.yaml")
    state = rollout.status(cluster)
    assert not state["running"] and not rollout.is_running(cluster) and "saving the result failed" in state["error"]


def test_unwritable_patch_file_is_refused_before_anything_changes(cluster, fake, tmp_path, monkeypatch):
    import os
    base = tmp_path / "cfg" / "clus"
    (base / "patch").mkdir(parents=True)
    (base / "patch" / "s.yaml").write_text(PATCH)
    monkeypatch.setattr(sources.config, "CONFIG_DIR", tmp_path / "cfg")
    sources.set_base_dir(cluster, "clus")
    p = patches.add_link(cluster, "patch/s.yaml", "worker")
    (base / "patch" / "s.yaml").chmod(0o444)
    (base / "patch").chmod(0o555)
    try:
        if os.access(base / "patch" / "s.yaml", os.W_OK):
            pytest.skip("running as root")
        for kw in ({"patch_id": p["id"]}, {"patch_id": p["id"], "delete": True}, {"path": "patch/new.yaml"}):
            with pytest.raises(rollout.RolloutError, match="no permission"):
                asyncio.run(rollout.validate(cluster, PATCH, "worker", "no-reboot", **kw))
        assert fake["applied"] == []
    finally:
        (base / "patch").chmod(0o755)
        (base / "patch" / "s.yaml").chmod(0o644)


def test_restart_during_rollout_is_marked_interrupted(cluster, fake):
    state = {"running": True, "paused": False, "started": "2026-01-01T00:00:00+00:00", "finished": None,
             "user": "admin", "actor": {"id": "admin", "name": "admin"}, "name": "a.yaml", "mode": "no-reboot",
             "target_label": "Workers", "ok": None, "saved": False, "error": None, "action": "new", "patch_id": None,
             "rollback_of": None, "canary": False, "sha256": "x",
             "nodes": [{"address": "10.0.1.1", "hostname": "w-1", "role": "worker", "removes": False, "status": "done", "error": None},
                       {"address": "10.0.1.2", "hostname": "w-2", "role": "worker", "removes": False, "status": "applying", "error": None},
                       {"address": "10.0.0.1", "hostname": "cp-1", "role": "controlplane", "removes": False, "status": "pending", "error": None}]}
    rollout._persist(cluster, state)
    rollout._runs.clear()  # as after a restart

    async def go():
        rollout.recover()

    asyncio.run(go())
    s = rollout.status(cluster)
    assert not s["running"] and s["error"] == rollout.INTERRUPTED
    assert [n["status"] for n in s["nodes"]] == ["done", "interrupted", "skipped"]
    assert audit.entries(cluster)[0]["error"] == rollout.INTERRUPTED
    assert audit.activity()[0]["action"] == "rollout.interrupted"


def test_unhealthy_etcd_stops_before_the_next_control_plane(cluster, fake):
    fake["etcd_down"].add("10.0.0.1")
    _rollout(cluster, PATCH, "controlplane", "no-reboot", name="a.yaml")
    assert [n for n, _ in fake["applied"]] == ["10.0.0.1"]
    nodes = rollout.status(cluster)["nodes"]
    assert nodes[0]["status"] == "failed" and "etcd is not healthy" in nodes[0]["error"]
    assert nodes[1]["status"] == "skipped"


def test_kubernetes_node_not_ready_stops(cluster, fake):
    fake["k8s"]["10.0.1.1"] = False
    _rollout(cluster, PATCH, "worker", "no-reboot", name="a.yaml")
    assert "Kubernetes node is not Ready" in rollout.status(cluster)["nodes"][0]["error"]


def _paused_rollout(cluster, fake, go: bool):
    async def run():
        plan = await rollout.validate(cluster, PATCH, "worker", "no-reboot", name="a.yaml", canary=True)
        rollout.start(cluster, plan["plan_id"], "admin")
        await _until(lambda: rollout.status(cluster)["paused"])
        assert [n for n, _ in fake["applied"]] == ["10.0.1.1"]  # only the first node so far
        rollout.decide(cluster, go, {"id": "admin", "name": "admin", "method": "password"})
        await _finish(cluster)

    asyncio.run(run())


def test_canary_continue(cluster, fake):
    _paused_rollout(cluster, fake, go=True)
    assert [n for n, _ in fake["applied"]] == ["10.0.1.1", "10.0.1.2"]
    assert rollout.status(cluster)["ok"] and patches.all_patches(cluster)


def test_canary_stop(cluster, fake):
    _paused_rollout(cluster, fake, go=False)
    state = rollout.status(cluster)
    assert [n["status"] for n in state["nodes"]] == ["done", "skipped"]
    assert not state["ok"] and "Stopped after the first node" in state["error"]
    assert patches.all_patches(cluster) == []  # stopped: the baseline is unchanged


def test_skip_unreachable(cluster, fake):
    scan = store.latest(cluster)
    next(n for n in scan["nodes"] if n["address"] == "10.0.1.2")["status"] = "unreachable"
    store.add_scan(cluster, scan)
    fake["dry_fail"].add("10.0.0.2")  # answers "connection refused" at dry-run time
    blocked = asyncio.run(rollout.validate(cluster, PATCH, "all", "no-reboot", name="a.yaml"))
    assert not blocked["ok"]  # without the option, one unreachable node blocks the rollout
    plan = _rollout(cluster, PATCH, "all", "no-reboot", name="a.yaml", skip_unreachable=True)
    assert sorted(n["hostname"] for n in plan["skipped"]) == ["cp-2", "w-2"]
    assert "Skipped because unreachable" in plan["warnings"][0]
    assert {"10.0.1.2", "10.0.0.2"}.isdisjoint(n for n, _ in fake["applied"])
