import pytest

from app import store, vault
from app.vault import Vault


@pytest.fixture
def v(tmp_path, monkeypatch):
    instance = Vault("x" * 40, tmp_path / "data", tmp_path / "tmp")
    monkeypatch.setattr(vault, "_vault", instance)
    return instance


def test_cluster_crud_and_isolation(v):
    a = store.add_cluster("Productie")
    b = store.add_cluster("Test lab")
    assert a["id"].startswith("productie-") and b["id"].startswith("test-lab-")
    s = store.settings(a["id"])
    s["base_dir"] = "prod"
    store.save_settings(a["id"], s)
    assert store.settings(b["id"])["base_dir"] == ""
    store.add_scan(a["id"], {"finished_at": "2026-01-01T00:00:00+00:00", "nodes": []})
    assert store.latest(b["id"]) is None

    store.rename_cluster(b["id"], "Lab")
    assert store.get_cluster(b["id"])["name"] == "Lab"
    store.delete_cluster(a["id"])
    assert [c["name"] for c in store.clusters()] == ["Lab"]
    assert not list(v.data_dir.glob(f"{a['id']}.*"))


def test_migrate_legacy_single_cluster(v):
    v.save("settings", b'{"base_dir": "kubertinus", "ignore": ["x"]}')
    v.save("results", b"[]")
    v.save("patches", b"[]")
    v.save("talosconfig", b"tc")
    v.save("patch-abc", b"p")
    store.migrate_legacy()
    (c,) = store.clusters()
    assert c["name"] == "kubertinus"
    assert store.settings(c["id"])["ignore"] == ["x"]
    assert v.load(f"{c['id']}.talosconfig") == b"tc"
    assert v.load(f"{c['id']}.patch-abc") == b"p"
    assert not v.exists("settings") and not v.exists("patch-abc")
    store.migrate_legacy()  # idempotent
    assert len(store.clusters()) == 1


def test_no_migration_on_fresh_install(v):
    store.migrate_legacy()
    assert store.clusters() == []
