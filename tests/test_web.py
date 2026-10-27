"""Route-level checks: who may change things, metrics, and notifications on scan changes."""
import pytest
from starlette.requests import Request

from app import config, vault
from app.vault import Vault

config.MASTER_KEY = config.MASTER_KEY or "x" * 40
config.ADMIN_PASSWORD = config.ADMIN_PASSWORD or "test"
config.PASSWORD_ENABLED = True
from app import auth, main, notify, scanner, store  # noqa: E402  (main validates config on import)

READ_ONLY_POSTS = {"/login", "/logout", "/api/scan", "/api/c/{cid}/scan"}


@pytest.fixture(autouse=True)
def v(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "_vault", Vault("x" * 40, tmp_path / "data", tmp_path / "tmp"))


def _request(session: dict) -> Request:
    return Request({"type": "http", "method": "POST", "path": "/settings/x/general", "headers": [],
                    "client": ("10.0.0.9", 1), "session": session, "query_string": b""})


def test_every_changing_route_requires_an_operator():
    posts = [r for r in main.app.routes if "POST" in getattr(r, "methods", set())]
    assert len(posts) > 15
    for r in posts:
        deps = {d.call for d in r.dependant.dependencies}
        if r.path in READ_ONLY_POSTS:
            assert auth.require_operator not in deps, r.path
        else:
            assert auth.require_operator in deps, r.path


def test_viewer_is_refused_and_logged(monkeypatch):
    from app import audit
    viewer = {"user": "oidc:1", "name": "Vera", "username": "vera", "method": "oidc", "operator": False}
    with pytest.raises(auth.OperatorRequired):
        auth.require_operator(_request(viewer))
    entry = audit.activity()[0]
    assert entry["action"] == "access.denied" and entry["actor"]["role"] == "viewer"
    auth.require_operator(_request({**viewer, "operator": True}))  # no exception


def test_operator_for_sessions_from_before_roles(monkeypatch):
    old_oidc = {"user": "oidc:1", "name": "Vera", "method": "oidc"}
    assert auth.is_operator(_request(old_oidc))
    monkeypatch.setattr(config, "OIDC_OPERATOR_ROLES", ["talos-operator"])
    assert not auth.is_operator(_request(old_oidc))
    assert auth.is_operator(_request({"user": "admin", "name": "admin", "method": "password"}))


def test_oidc_operator_roles(monkeypatch):
    from app import oidc
    assert oidc.is_operator(set(), set())  # nothing configured: everyone who may log in
    monkeypatch.setattr(config, "OIDC_OPERATOR_ROLES", ["talos-operator"])
    monkeypatch.setattr(config, "OIDC_OPERATOR_GROUPS", ["/platform/ops"])
    assert oidc.is_operator({"talos-operator"}, set()) and oidc.is_operator(set(), {"platform/ops"})
    assert not oidc.is_operator({"viewer"}, {"dev"})


def test_metrics_need_the_token(monkeypatch):
    from fastapi.testclient import TestClient
    c = store.add_cluster("prod")
    store.add_scan(c["id"], {"finished_at": "2026-01-01T00:00:00+00:00", "nodes": [
        {"address": "10.0.0.1", "hostname": "cp-1", "role": "controlplane", "status": "drift", "drift_count": 2}]})
    client = TestClient(main.app)
    monkeypatch.setattr(config, "METRICS_TOKEN", None)
    assert client.get("/metrics").status_code == 404
    monkeypatch.setattr(config, "METRICS_TOKEN", "s3cret")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = client.get("/metrics", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200
    assert 'talos_cm_nodes{cluster="prod",role="controlplane",status="drift"} 1' in r.text
    assert 'talos_cm_node_drift_paths{cluster="prod",node="cp-1",role="controlplane"} 2' in r.text


def test_notifications_only_for_changes(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send", lambda event, cluster, text, **f: sent.append((event, text)))
    cluster = {"id": "c", "name": "prod"}
    prev = {"nodes": [{"address": "a", "hostname": "w-1", "status": "in-sync"},
                      {"address": "b", "hostname": "w-2", "status": "drift"}], "peers": {}}
    scan = {"nodes": [{"address": "a", "hostname": "w-1", "status": "drift"},
                      {"address": "b", "hostname": "w-2", "status": "in-sync"}],
            "peers": {"worker": [{"path": "machine.x", "intended": False}]}}
    scanner._notify_changes(cluster, prev, scan)
    assert [e for e, _ in sent] == ["nodes.degraded", "nodes.recovered", "consistency.unplanned"]
    sent.clear()
    scanner._notify_changes(cluster, scan, scan)  # nothing changed: nothing sent
    assert sent == []


def test_notify_posts_json(monkeypatch):
    import asyncio
    posted = []
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URLS", ["https://hooks.example/1"])
    monkeypatch.setattr(notify, "_post", lambda url, payload: posted.append((url, payload)))

    async def go():
        notify.send("rollout.failed", {"name": "prod"}, "Rollout failed", patch="a.yaml")
        await asyncio.sleep(0.05)

    asyncio.run(go())
    url, payload = posted[0]
    assert url == "https://hooks.example/1" and payload["event"] == "rollout.failed"
    assert payload["text"].endswith("Rollout failed") and payload["cluster"] == "prod" and payload["patch"] == "a.yaml"


def test_remove_from_baseline_can_delete_the_file(tmp_path, monkeypatch):
    import re
    from fastapi.testclient import TestClient
    from app import patches, sources
    base = tmp_path / "cfg" / "clus" / "patch"
    base.mkdir(parents=True)
    (base / "n4.yaml").write_text("machine: {}\n")
    (base / "keep.yaml").write_text("machine: {}\n")
    monkeypatch.setattr(sources.config, "CONFIG_DIR", tmp_path / "cfg")
    c = store.add_cluster("prod")
    sources.set_base_dir(c["id"], "clus")
    gone = patches.add_link(c["id"], "patch/n4.yaml", "node:n4")
    kept = patches.add_link(c["id"], "patch/keep.yaml", "node:n5")
    client = TestClient(main.app, base_url="https://testserver")
    client.post("/login", data={"password": config.ADMIN_PASSWORD})
    page = client.get(f"/settings/{c['id']}").text
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    assert "linked" in page  # linked files are listed, marked
    client.post(f"/settings/{c['id']}/patches/{gone['id']}/delete", data={"csrf": csrf, "delete_file": "1"})
    client.post(f"/settings/{c['id']}/patches/{kept['id']}/delete", data={"csrf": csrf})
    assert patches.all_patches(c["id"]) == []
    assert not (base / "n4.yaml").exists() and (base / "keep.yaml").exists()


def _login(client):
    import re
    client.post("/login", data={"password": config.ADMIN_PASSWORD})
    return lambda page: re.search(r'name="csrf-token" content="([^"]+)"', client.get(page).text).group(1)


def test_settings_target_with_ticked_and_typed_nodes(monkeypatch):
    from fastapi.testclient import TestClient
    from app import patches
    monkeypatch.setattr(scanner, "request", lambda cid: None)  # no talosconfig here: a rescan would empty the node list
    c = store.add_cluster("prod")
    store.add_scan(c["id"], {"finished_at": "2026-01-01T00:00:00+00:00", "nodes": [
        {"address": "10.0.0.1", "hostname": "cp-1", "role": "controlplane", "status": "in-sync"},
        {"address": "10.0.1.1", "hostname": "w-1", "role": "worker", "status": "in-sync"},
        {"address": "10.0.1.2", "hostname": "w-2", "role": "worker", "status": "in-sync"}]})
    p = patches.add(c["id"], "odd.yaml", b"machine: {}\n", "all")
    client = TestClient(main.app, base_url="https://testserver")
    csrf = _login(client)(f"/settings/{c['id']}")
    url = f"/settings/{c['id']}/patches/{p['id']}/target"
    client.post(url, data={"csrf": csrf, "target": "node", "node_names": ["w-1", "w-2"], "node_name": "w-9"})
    assert patches.get(c["id"], p["id"])["target"] == "nodes:w-1,w-2,w-9"
    page = client.get(f"/settings/{c['id']}").text
    import re
    assert re.search(r'value="w-1"[^>]*checked', page) and not re.search(r'value="cp-1"[^>]*checked', page)
    assert 'value="w-9"' in page  # the typed, not yet scanned node is kept in the text field
    client.post(url, data={"csrf": csrf, "target": "node", "node_names": ["w-2"]})  # untick w-1, drop w-9
    assert patches.get(c["id"], p["id"])["target"] == "node:w-2"
    client.post(url, data={"csrf": csrf, "target": "node"})  # nothing selected: refused, unchanged
    assert patches.get(c["id"], p["id"])["target"] == "node:w-2"


def test_try_apply_uses_the_roles_of_the_selected_nodes(monkeypatch):
    import asyncio
    from app import patches, sources, talos
    c = store.add_cluster("prod")
    for role in patches.ROLES:
        sources.save_upload(c["id"], role, f"version: v1alpha1\nmachine: {{type: {role}}}\n".encode())

    async def build_baseline(cid, role, applied):  # the patch only fits control planes
        if role == "worker":
            raise talos.TalosError("Patches (new patch) cannot be applied: no such field")
        return ""

    monkeypatch.setattr(patches, "build_baseline", build_baseline)
    run = lambda target, roles=None: asyncio.run(patches.try_apply(c["id"], b"x: 1\n", target, roles))  # noqa: E731
    assert run("nodes:cp-1,cp-2", {"controlplane"}) is None
    assert "worker.yaml" in run("nodes:cp-1,w-1", {"controlplane", "worker"})
    assert run("nodes:new-1,new-2") is None  # roles unknown: fitting one role is enough
    assert "worker.yaml" in run("all")
