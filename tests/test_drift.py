import yaml

from app import drift

BASELINE = """\
version: v1alpha1
machine:
  type: worker
  token: supersecrettoken
  ca:
    crt: Y2VydA==
    key: ""
  install:
    disk: /dev/sda
  network:
    hostname: base
  sysctls:
    vm.max_map_count: "262144"
cluster:
  token: abc.def
  network:
    cni:
      name: flannel
---
apiVersion: v1alpha1
kind: HostnameConfig
auto: stable
"""

ACTUAL = """\
version: v1alpha1
machine:
  type: worker
  token: supersecrettoken
  ca:
    crt: Y2VydA==
    key: ""
  install:
    disk: /dev/nvme0n1
  network:
    hostname: worker-1
  sysctls:
    vm.max_map_count: "524288"
    net.core.somaxconn: "1024"
cluster:
  token: rotated.token
  network:
    cni:
      name: none
---
apiVersion: v1alpha1
kind: HostnameConfig
hostname: worker-1
---
apiVersion: v1alpha1
kind: ExtensionServiceConfig
name: nut
environment: [A=1]
"""


def _by_path(changes):
    return {c["path"]: c for c in changes}


def test_detects_added_changed_removed_and_ignores():
    result = drift.compute(BASELINE, ACTUAL, drift.DEFAULT_IGNORE)
    changes = _by_path(result["changes"])

    assert changes["machine.sysctls.vm.max_map_count"]["type"] == "changed"
    assert changes["machine.sysctls.net.core.somaxconn"]["type"] == "added"
    assert changes["cluster.network.cni.name"]["actual"] == "none"
    # Added documents are reported per field, without apiVersion/kind/name noise.
    assert changes["ExtensionServiceConfig[nut].environment[0]"]["actual"] == "A=1"
    assert "ExtensionServiceConfig[nut].kind" not in changes
    # Default ignore rules: hostname, install disk and the HostnameConfig hostname.
    assert not any(p.startswith(("machine.network.hostname", "machine.install", "HostnameConfig.hostname")) for p in changes)
    # ...but other HostnameConfig fields are still compared.
    assert changes["HostnameConfig.auto"]["type"] == "removed"
    assert {i["rule"] for i in result["ignored"]} >= {"machine.install.disk", "HostnameConfig.hostname"}


def test_secrets_are_masked_but_drift_is_visible():
    result = drift.compute(BASELINE, ACTUAL, [])
    changes = _by_path(result["changes"])

    token = changes["cluster.token"]
    assert token["baseline"].startswith("***sha256:")
    assert token["baseline"] != token["actual"]
    # An unchanged secret produces no drift.
    assert "machine.token" not in changes
    assert "supersecrettoken" not in result["diff"]
    assert "abc.def" not in result["diff"] and "rotated.token" not in result["diff"]


def test_identical_configs_are_in_sync():
    assert drift.compute(BASELINE, BASELINE, [])["changes"] == []


def test_container_emptied_by_ignore_is_not_drift():
    base = "version: v1alpha1\nmachine:\n  type: worker\n"
    actual = "version: v1alpha1\nmachine:\n  type: worker\n  network:\n    hostname: w-1\n"
    result = drift.compute(base, actual, ["machine.network.hostname"])
    assert result["changes"] == []
    assert "network" not in result["diff"]


def test_is_ignored_matches_ancestors_and_globs():
    assert drift.is_ignored("machine.network.interfaces[0].addresses[1]", ["machine.network.interfaces"])
    assert drift.is_ignored("machine.kubelet.extraArgs.node-ip", ["machine.kubelet.extraArgs.*"])
    assert drift.is_ignored("HostnameConfig", ["HostnameConfig*"])
    assert not drift.is_ignored("machine.network.nameservers", ["machine.network.interfaces"])


def test_brackets_are_literal_and_index_wildcard():
    vip = "Layer2VIPConfig[192.168.178.230].link"
    assert drift.is_ignored(vip, ["Layer2VIPConfig[192.168.178.230]"])
    assert drift.is_ignored(vip, ["Layer2VIPConfig[*]"])
    assert not drift.is_ignored(vip, ["Layer2VIPConfig[10.0.0.1]"])
    assert drift.is_ignored("LinkConfig[ens18].addresses[0].address", ["LinkConfig[*].addresses"])
    assert not drift.is_ignored("LinkConfig[ens18].mtu", ["LinkConfig[*].addresses"])
    assert not drift.is_ignored("machine.kubelet.extraArgs.a.b", ["machine.*.b"])
    assert drift.is_ignored("machine.kubelet.extraArgs.a", ["machine.**.a"])


def test_added_doc_partially_ignored():
    base = "version: v1alpha1\nmachine: {type: controlplane}\n"
    actual = base + (
        "---\napiVersion: v1alpha1\nkind: LinkConfig\nname: ens18\nup: true\nmtu: 9000\n"
        "addresses: [{address: 10.0.0.2/24}]\n"
    )
    result = drift.compute(base, actual, ["LinkConfig[*].addresses"])
    assert sorted(c["path"] for c in result["changes"]) == ["LinkConfig[ens18].mtu", "LinkConfig[ens18].up"]
    assert [c["path"] for c in result["ignored"]] == ["LinkConfig[ens18].addresses[0].address"]


def test_mark_outliers():
    nodes = [{"role": "worker", "status": "drift", "shape": s} for s in ("a", "a", "b")]
    drift.mark_outliers(nodes)
    assert [n["outlier"] for n in nodes] == [False, False, True]


def test_no_outliers_without_majority():
    nodes = [{"role": "controlplane", "status": "drift", "shape": s} for s in ("a", "b", "c")]
    drift.mark_outliers(nodes)
    assert not any(n["outlier"] for n in nodes)


def test_shape_ignores_per_node_values():
    a = [{"path": "LinkConfig[ens18]", "type": "added", "actual": {"addresses": ["10.0.0.1/24"]}}]
    b = [{"path": "LinkConfig[ens18]", "type": "added", "actual": {"addresses": ["10.0.0.2/24"]}}]
    assert drift.shape(a) == drift.shape(b)


def test_vips_from_new_and_legacy_config():
    docs = drift.parse_config(
        "version: v1alpha1\nmachine:\n  network:\n    interfaces:\n      - interface: eth0\n        vip: {ip: 10.0.0.5}\n"
        "---\napiVersion: v1alpha1\nkind: Layer2VIPConfig\nname: 10.0.0.9\nlink: eth0\n"
    )
    assert drift.vips(docs) == {"10.0.0.5", "10.0.0.9"}


def _cfg(hostname, extra=""):
    return f"version: v1alpha1\nmachine:\n  type: worker\n  network: {{hostname: {hostname}}}\n  token: abc\n{extra}"


def test_peer_differences_unplanned_and_majority():
    base = _cfg("x")
    nodes = [
        {"hostname": "w-1", "actual": _cfg("w-1", "  sysctls: {a: '1'}\n"), "baseline": base},
        {"hostname": "w-2", "actual": _cfg("w-2", "  sysctls: {a: '1'}\n"), "baseline": base},
        {"hostname": "w-3", "actual": _cfg("w-3", "  sysctls: {a: '2'}\n"), "baseline": base},
    ]
    diffs = drift.peer_differences(nodes, drift.DEFAULT_IGNORE)
    assert [d["path"] for d in diffs] == ["machine.sysctls.a"]
    d = diffs[0]
    assert not d["intended"] and d["odd"] == ["w-3"] and d["values"] == {"w-1": "1", "w-2": "1", "w-3": "2"}


def test_peer_differences_intended_via_patch_and_absent():
    base, patched = _cfg("x"), _cfg("x", "  sysctls: {a: '1'}\n")
    nodes = [
        {"hostname": "w-1", "actual": _cfg("w-1", "  sysctls: {a: '1'}\n"), "baseline": patched},
        {"hostname": "w-2", "actual": _cfg("w-2"), "baseline": base},
    ]
    d = drift.peer_differences(nodes, drift.DEFAULT_IGNORE)[0]
    assert d["intended"] and d["absent"] == ["w-2"] and d["values"]["w-2"] is None
    assert sorted(d["odd"]) == ["w-1", "w-2"]  # no strict majority with two nodes
    # The same difference without a patch explaining it is unplanned.
    nodes[0]["baseline"] = base
    assert not drift.peer_differences(nodes, drift.DEFAULT_IGNORE)[0]["intended"]


def test_peer_differences_respects_ignore_and_masks_secrets():
    nodes = [
        {"hostname": "w-1", "actual": _cfg("w-1"), "baseline": None},
        {"hostname": "w-2", "actual": _cfg("w-2").replace("token: abc", "token: xyz"), "baseline": None},
    ]
    diffs = drift.peer_differences(nodes, drift.DEFAULT_IGNORE)
    assert [d["path"] for d in diffs] == ["machine.token"]
    assert all(v.startswith("***sha256:") for v in diffs[0]["values"].values())
    assert drift.peer_differences(nodes, [*drift.DEFAULT_IGNORE, "machine.token"]) == []


def test_keep_ignored_takes_node_values_for_ignored_paths():
    desired = (
        "version: v1alpha1\nmachine:\n  network:\n    hostname: base\n    interfaces:\n"
        "      - interface: eth0\n        addresses: [10.0.0.9/24]\n        mtu: 9000\n"
        "  install: {disk: /dev/sda}\n  sysctls: {a: '1'}\n"
        "---\napiVersion: v1alpha1\nkind: HostnameConfig\nhostname: base\n"
    )
    actual = (
        "version: v1alpha1\nmachine:\n  network:\n    hostname: w-1\n    interfaces:\n"
        "      - interface: eth0\n        addresses: [10.0.0.21/24]\n        mtu: 1500\n"
        "  install: {disk: /dev/nvme0n1}\n  sysctls: {a: '0', b: '2'}\n"
        "---\napiVersion: v1alpha1\nkind: HostnameConfig\nhostname: w-1\n"
    )
    docs = list(yaml.safe_load_all(drift.keep_ignored(desired, actual, drift.DEFAULT_IGNORE)))
    machine = docs[0]["machine"]
    assert machine["network"]["hostname"] == "w-1" and machine["install"]["disk"] == "/dev/nvme0n1"
    assert machine["network"]["interfaces"][0] == {"interface": "eth0", "addresses": ["10.0.0.21/24"], "mtu": 9000}
    assert machine["sysctls"] == {"a": "1"}  # not ignored: the baseline wins
    assert docs[1]["hostname"] == "w-1"


def test_keep_ignored_drops_ignored_values_the_node_lacks():
    """Talos moves cluster.proxy into a KubeProxyConfig document; the node has no cluster.proxy."""
    desired = "version: v1alpha1\ncluster:\n  proxy: {disabled: true}\n  network: {cni: {name: none}, dnsDomain: x}\n"
    actual = "version: v1alpha1\ncluster:\n  network: {dnsDomain: x}\n"
    rules = ["cluster.proxy.disabled", "cluster.network.cni.name"]
    doc = yaml.safe_load(drift.keep_ignored(desired, actual, rules))
    assert doc["cluster"] == {"network": {"dnsDomain": "x"}}


def test_keep_ignored_drops_only_empty_defaults_the_node_lacks():
    desired = (
        "version: v1alpha1\ncluster:\n  network: {dnsDomain: '', podSubnets: []}\n  etcd: {x: 1}\n"
        "machine: {kubelet: {disableManifestsDirectory: false}}\n"
        "---\napiVersion: v1alpha1\nkind: KubeNodeConfig\nlabels: {node-role.kubernetes.io/control-plane: ''}\n"
    )
    actual = (
        "apiVersion: v1alpha1\nkind: KubeNodeConfig\nlabels: {node-role.kubernetes.io/control-plane: ''}\n"
        "---\nversion: v1alpha1\ncluster: {etcd: {x: 1}}\nmachine: {kubelet: {}}\n"
    )
    docs = list(yaml.safe_load_all(drift.keep_ignored(desired, actual, [])))
    assert docs[0]["kind"] == "KubeNodeConfig"  # the node's document order
    assert docs[0]["labels"] == {"node-role.kubernetes.io/control-plane": ""}  # "" the node has: kept
    assert docs[1]["cluster"] == {"etcd": {"x": 1}}
    assert docs[1]["machine"]["kubelet"]["disableManifestsDirectory"] is False


def test_config_diff_masks_secrets():
    cur = "version: v1alpha1\nmachine:\n  ca: {crt: abc, key: SECRETKEY}\n  sysctls: {a: '1'}\n"
    new = cur.replace("a: '1'", "a: '2'")
    diff = drift.config_diff(cur, new)
    assert "SECRETKEY" not in diff and "+    a: '2'" in diff and "***sha256:" in diff
    assert drift.config_diff(cur, cur) == ""


LABELS = "apiVersion: v1alpha1\nkind: KubeNodeConfig\nlabels:\n  node-role.kubernetes.io/control-plane: ''\n  zone: a\n"


def test_empty_label_values_are_real_values():
    without = "apiVersion: v1alpha1\nkind: KubeNodeConfig\nlabels:\n  zone: a\n"
    changes = drift.compute(LABELS, without, [])["changes"]
    assert [(c["type"], c["path"]) for c in changes] == [("removed", "KubeNodeConfig.labels.node-role.kubernetes.io/control-plane")]
    assert "control-plane" in drift.config_diff(LABELS, without)
    # Empty schema fields stay noise, as before.
    assert drift.compute("version: v1alpha1\ncluster: {network: {dnsDomain: ''}}\n", "version: v1alpha1\n", [])["changes"] == []


def test_keep_ignored_without_taking_values_for_a_new_node():
    desired = ("version: v1alpha1\nmachine:\n  network: {hostname: new-node}\ncluster:\n  proxy: {disabled: true}\n"
               "  network: {cni: {name: none}, dnsDomain: ''}\n  etcd: {x: 1}\n")
    reference = "version: v1alpha1\nmachine:\n  network: {hostname: old-node}\ncluster:\n  etcd: {x: 1}\n"
    rules = [*drift.DEFAULT_IGNORE, "cluster.proxy.disabled", "cluster.network.cni.name"]
    doc = yaml.safe_load(drift.keep_ignored(desired, reference, rules, take=False))
    assert doc["machine"]["network"]["hostname"] == "new-node"  # its own value, not the reference node's
    assert doc["cluster"] == {"etcd": {"x": 1}}
