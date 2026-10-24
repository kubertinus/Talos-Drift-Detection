from app import drift, patches


def _p(pid, target):
    return {"id": pid, "name": pid, "target": target}


def test_applicable_order_and_targets():
    index = [_p("node1", "node:cp-1"), _p("cp", "controlplane"), _p("all", "all"), _p("w", "worker"), _p("ip", "node:10.0.0.2")]
    assert [p["id"] for p in patches.applicable("controlplane", "cp-1", "10.0.0.1", index)] == ["all", "cp", "node1"]
    assert [p["id"] for p in patches.applicable("worker", "w-1", "10.0.0.2", index)] == ["all", "w", "ip"]


def test_check_yaml():
    assert patches.check_yaml(b"machine:\n  sysctls: {a: '1'}\n") is None
    assert patches.check_yaml(b"- op: add\n  path: /x\n  value: 1\n") is None
    assert "line" in patches.check_yaml(b"machine: [broken\n")
    assert patches.check_yaml(b"just a string") is not None


def test_valid_target():
    assert patches.valid_target("all") and patches.valid_target("node:cp-1")
    assert not patches.valid_target("node:") and not patches.valid_target("foo")


def test_empty_and_null_values_are_not_drift():
    base = "version: v1alpha1\nmachine:\n  type: worker\n  install: {disk: /dev/sda}\n"
    actual = "version: v1alpha1\nmachine:\n  type: worker\n  certSANs: []\n  install: {disk: /dev/sda, wipe: null}\n  kubelet: {}\ncluster:\n  network: {dnsDomain: ''}\n"
    assert drift.compute(base, actual, [])["changes"] == []
