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


def test_node_selection_targets():
    assert patches.nodes_target(["w-1"]) == "node:w-1"
    assert patches.nodes_target(["w-1", " w-2", "w-1", ""]) == "nodes:w-1,w-2"
    assert not patches.valid_target(patches.nodes_target([]))
    assert patches.valid_target("nodes:w-1,w-2") and not patches.valid_target("nodes:")
    assert patches.target_label("nodes:w-1,w-2") == "Nodes w-1, w-2"
    assert patches.target_label("node:w-1") == "Node w-1"
    index = [_p("sel", "nodes:w-1,10.0.0.3"), _p("all", "all")]
    assert [p["id"] for p in patches.applicable("worker", "w-1", "10.0.0.1", index)] == ["all", "sel"]
    assert [p["id"] for p in patches.applicable("worker", "w-3", "10.0.0.3", index)] == ["all", "sel"]
    assert [p["id"] for p in patches.applicable("worker", "w-2", "10.0.0.2", index)] == ["all"]


def test_dry_run_summary_leaves_out_the_diff():
    from app import talos
    out = ("Dry run summary:\nApplied configuration without a reboot (skipped in dry-run).\nConfig diff:\n\n"
           "--- a\n+++ b\n         key: LS0tPRIVATE\n")
    assert talos.dry_run_summary(out) == "Applied configuration without a reboot."
    assert talos.dry_run_summary("") == ""


def test_dry_run_changes_counts_only_real_lines():
    from app import talos
    out = "Dry run summary:\nApplied.\nConfig diff:\n\n--- a\n+++ b\n@@ -1 +1 @@\n context\n-    labels: x\n+\n+    other: y\n"
    assert talos.dry_run_changes(out) == 2
    assert talos.dry_run_changes("Dry run summary:\nApplied.\n") == 0
