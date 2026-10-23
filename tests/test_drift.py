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
