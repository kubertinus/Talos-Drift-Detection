import asyncio

import pytest
import yaml

from app import nodegen, patches, sources, store, talos, vault
from app.vault import Vault

NODE_PATCH = ("apiVersion: v1alpha1\nkind: HostnameConfig\nauto: off\nhostname: w-1\n---\n"
              "apiVersion: v1alpha1\nkind: LinkConfig\nname: ens18\naddresses:\n  - address: 10.0.1.1/24\n")


def _merge(base, patch):
    if isinstance(base, dict) and isinstance(patch, dict):
        return {**base, **{k: _merge(base.get(k), v) for k, v in patch.items()}}
    return patch


@pytest.fixture
def cluster(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "_vault", Vault("x" * 40, tmp_path / "data", tmp_path / "tmp"))
    monkeypatch.setattr(nodegen.talos.config, "TMP_DIR", tmp_path / "tmp")
    nodegen._downloads.clear()
    c = store.add_cluster("prod")
    for role in patches.ROLES:
        sources.save_upload(c["id"], role, f"version: v1alpha1\nmachine:\n  type: {role}\n".encode())
    nodes = [{"address": "10.0.1.1", "hostname": "w-1", "role": "worker", "status": "in-sync"},
             {"address": "10.0.0.1", "hostname": "cp-1", "role": "controlplane", "status": "in-sync"}]
    from datetime import datetime, timezone
    store.add_scan(c["id"], {"finished_at": datetime.now(timezone.utc).isoformat(), "nodes": nodes, "peers": {}})
    patches.add(c["id"], "all.yaml", b"machine: {sysctls: {a: '1'}}\n", "all")
    patches.add(c["id"], "workers.yaml", b"machine: {kubelet: {extraArgs: {max-pods: '150'}}}\n", "worker")
    patches.add(c["id"], "w-1.yaml", NODE_PATCH.encode(), "node:w-1")
    patches.add(c["id"], "cp-1.yaml", b"machine: {sysctls: {cp: 'only'}}\n", "node:cp-1")

    async def patch_config(base_path, patch_paths):
        docs = list(yaml.safe_load_all(open(base_path)))
        for p in patch_paths:
            for d in yaml.safe_load_all(open(p)):
                if d.get("kind"):
                    docs.append(d)
                else:
                    docs[0] = _merge(docs[0], d)
        return yaml.safe_dump_all(docs)

    validated = []

    async def validate_config(text, mode):
        validated.append(mode)

    monkeypatch.setattr(talos, "patch_config", patch_config)
    monkeypatch.setattr(talos, "validate_config", validate_config)
    return c["id"]


def test_template_replaces_hostname_and_address(cluster):
    text = nodegen.template_text(cluster, "w-1", "w-2", "10.0.1.2")
    assert "hostname: w-2" in text and "10.0.1.2/24" in text and "w-1" not in text and "10.0.1.1" not in text
    assert nodegen.templates(cluster, "worker") == [{"hostname": "w-1", "address": "10.0.1.1", "patches": ["w-1.yaml"]}]


def test_generate_uses_all_and_role_patches_plus_the_new_node_patch(cluster):
    node_patch = nodegen.template_text(cluster, "w-1", "w-2", "10.0.1.2")
    res = asyncio.run(nodegen.generate(cluster, "worker", "W-2", "10.0.1.2", node_patch))
    assert res["patches"] == ["all.yaml", "workers.yaml", "w-2 (new node)"]  # not w-1.yaml or cp-1.yaml
    host, config = nodegen.download(cluster, res["download_id"])
    docs = list(yaml.safe_load_all(config))
    assert host == "w-2" and docs[0]["machine"]["sysctls"] == {"a": "1"} and "cp" not in docs[0]["machine"]["sysctls"]
    assert any(d.get("kind") == "HostnameConfig" and d["hostname"] == "w-2" for d in docs)
    with pytest.raises(nodegen.NodeGenError, match="expired or was already downloaded"):
        nodegen.download(cluster, res["download_id"])  # once only


def test_generate_refused_with_unplanned_drift(cluster):
    scan = store.latest(cluster)
    scan["nodes"][0]["status"] = "drift"
    store.add_scan(cluster, scan)
    with pytest.raises(nodegen.NodeGenError, match="Unplanned drift"):
        asyncio.run(nodegen.generate(cluster, "worker", "w-2", "", ""))
    scan["nodes"][0]["status"] = "in-sync"
    scan["peers"] = {"worker": [{"path": "machine.x", "intended": False}]}
    store.add_scan(cluster, scan)
    assert "unplanned difference" in nodegen.readiness(cluster)[0][0]


@pytest.mark.parametrize("hostname,address,match", [
    ("w-1", "", "already a node"), ("w-9", "10.0.0.1", "already a node"), ("Bad_Name!", "", "valid hostname")])
def test_generate_rejects_bad_input(cluster, hostname, address, match):
    with pytest.raises(nodegen.NodeGenError, match=match):
        asyncio.run(nodegen.generate(cluster, "worker", hostname, address, ""))


def test_save_node_patch_registers_it_for_the_new_node(cluster):
    p = nodegen.save_node_patch(cluster, "w-2", "machine: {}\n")
    assert p["target"] == "node:w-2" and p["name"] == "w-2.yaml"


def test_warns_when_nothing_sets_the_hostname(cluster):
    res = asyncio.run(nodegen.generate(cluster, "worker", "w-2", "10.0.1.2", ""))
    assert any("sets the hostname w-2" in w for w in res["warnings"])
    res = asyncio.run(nodegen.generate(cluster, "worker", "w-3", "10.0.1.3", nodegen.template_text(cluster, "w-1", "w-3", "10.0.1.3")))
    assert not any("sets the hostname" in w for w in res["warnings"])


def test_node_patch_is_never_registered_twice(cluster):
    nodegen.save_node_patch(cluster, "w-2", "machine: {}\n")
    with pytest.raises(nodegen.NodeGenError, match="already has a node patch"):
        nodegen.save_node_patch(cluster, "w-2", "machine: {}\n")
    res = asyncio.run(nodegen.generate(cluster, "worker", "w-2", "10.0.1.2", ""))
    assert any("already has a node patch" in w for w in res["warnings"])
