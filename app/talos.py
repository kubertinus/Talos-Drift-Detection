"""Thin async wrapper around the talosctl CLI."""
import asyncio
import ipaddress
import json
import os
import re
import tempfile

import yaml

from . import config


class TalosError(Exception):
    pass


async def _exec(*args: str, timeout: int | None = None, with_stderr: bool = False) -> str:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(config.TMP_DIR)}
    proc = await asyncio.create_subprocess_exec(
        config.TALOSCTL,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout or config.NODE_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TalosError(f"talosctl {args[0]} timed out")
    if proc.returncode != 0:
        msg = err.decode(errors="replace").strip().splitlines()
        raise TalosError(msg[-1][:300] if msg else f"talosctl exited with {proc.returncode}")
    return out.decode() + (err.decode(errors="replace") if with_stderr else "")


async def _run(talosconfig: str, *args: str, endpoint: str | None = None, timeout: int | None = None,
               with_stderr: bool = False) -> str:
    """Run talosctl against the cluster. `endpoint` overrides the talosconfig endpoints,
    needed when those are empty (as in a freshly generated talosconfig)."""
    extra = ["--endpoints", endpoint] if endpoint else []
    return await _exec("--talosconfig", talosconfig, *extra, *args, timeout=timeout, with_stderr=with_stderr)


async def patch_config(base_path: str, patch_paths: list[str]) -> str:
    """Apply patches to a machine config offline, with Talos' own patch semantics."""
    args = ["machineconfig", "patch", base_path]
    for p in patch_paths:
        args += ["--patch", f"@{p}"]
    return await _exec(*args)


async def validate_config(config_text: str, mode: str) -> None:
    """`talosctl validate` on a config (raises TalosError with Talos' message when it is invalid)."""
    config.TMP_DIR.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="validate-", suffix=".yaml", dir=config.TMP_DIR)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(config_text)
        await _exec("validate", "--config", path, "--mode", mode)
    finally:
        os.unlink(path)


def _json_stream(text: str):
    """talosctl -o json prints concatenated JSON objects, not an array."""
    dec = json.JSONDecoder()
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        yield obj


def _order_addresses(addresses: list[str]) -> list[str]:
    """IPv4 first, otherwise keep the order Talos reports them in."""

    def rank(a: str):
        try:
            return 0 if ipaddress.ip_address(a).version == 4 else 1
        except ValueError:
            return 2

    return sorted(addresses, key=rank)


def context_nodes(talosconfig_text: str) -> tuple[list[str], list[str]]:
    """Return (endpoints, nodes) of the current talosconfig context."""
    cfg = yaml.safe_load(talosconfig_text) or {}
    ctx = (cfg.get("contexts") or {}).get(cfg.get("context"), {})
    return list(ctx.get("endpoints") or []), list(ctx.get("nodes") or [])


async def discover(talosconfig: str, via: str, direct: bool = False) -> list[dict]:
    """List cluster members via the discovery service."""
    out = await _run(talosconfig, "-n", via, "get", "members", "-o", "json", endpoint=via if direct else None)
    members = []
    for obj in _json_stream(out):
        spec = obj.get("spec") or {}
        addresses = _order_addresses(spec.get("addresses") or [])
        if not addresses:
            continue
        version = re.search(r"v\d+\.\d+\.\d+\S*?(?=\)|$)", spec.get("operatingSystem") or "")
        members.append(
            {
                "address": addresses[0],
                "addresses": addresses,
                "hostname": spec.get("hostname") or addresses[0],
                "role": spec.get("machineType") or "unknown",
                "talos_version": version.group(0) if version else None,
            }
        )
    return members


async def machine_config(talosconfig: str, node: str, direct: bool = False) -> str:
    """Return the running machine config of a node as (multi-doc) YAML."""
    out = await _run(talosconfig, "-n", node, "get", "machineconfig", "v1alpha1", "-o", "yaml", endpoint=node if direct else None)
    for doc in yaml.safe_load_all(out):
        if isinstance(doc, dict) and "spec" in doc:
            spec = doc["spec"]
            return spec if isinstance(spec, str) else yaml.safe_dump(spec)
    raise TalosError("no machineconfig resource in talosctl output")


async def apply_config(
    talosconfig: str, node: str, config_path: str, mode: str, direct: bool = False, dry_run: bool = False
) -> str:
    """Replace the machine config of one node; with dry_run only report what would change."""
    args = ["-n", node, "apply-config", "--file", config_path, "--mode", mode]
    if dry_run:
        args.append("--dry-run")
    # The dry-run summary and diff go to stderr.
    return await _run(talosconfig, *args, endpoint=node if direct else None, timeout=max(config.NODE_TIMEOUT, 120),
                      with_stderr=True)


def dry_run_summary(output: str) -> str:
    """What Talos would do, e.g. 'Applied configuration without a reboot', without the config diff
    (talosctl prints that unmasked, secrets included)."""
    lines = [line.strip() for line in output.splitlines()]
    if "Dry run summary:" in lines:
        lines = lines[lines.index("Dry run summary:") + 1:]
    summary = []
    for line in lines:
        if not line or line.startswith("Config diff"):
            break
        summary.append(line.replace(" (skipped in dry-run)", ""))
    return " ".join(summary)


def dry_run_changes(output: str) -> int:
    """Number of changed lines in talosctl's own dry-run diff (counted only, never shown: it is unmasked)."""
    lines = output.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("--- ")), len(lines))
    return sum(1 for line in lines[start:] if line[:1] in "+-" and not line.startswith(("+++", "---")) and line[1:].strip())


async def node_ready(talosconfig: str, node: str, direct: bool = False) -> bool:
    """True when the node reports itself running and ready (e.g. after a reboot)."""
    try:
        out = await _run(talosconfig, "-n", node, "get", "machinestatus", "-o", "json", endpoint=node if direct else None)
    except TalosError:
        return False
    for obj in _json_stream(out):
        spec = obj.get("spec") or {}
        return spec.get("stage") == "running" and bool((spec.get("status") or {}).get("ready"))
    return False


async def etcd_healthy(talosconfig: str, node: str, direct: bool = False) -> bool:
    """Whether the etcd service on a control plane is running and healthy."""
    try:
        out = await _run(talosconfig, "-n", node, "get", "service", "etcd", "-o", "json", endpoint=node if direct else None)
    except TalosError:
        return False
    for obj in _json_stream(out):
        spec = obj.get("spec") or {}
        return bool(spec.get("running")) and bool(spec.get("healthy"))
    return False


async def kubernetes_node_ready(talosconfig: str, node: str, hostname: str, direct: bool = False) -> bool | None:
    """The node's Kubernetes Ready condition as Talos sees it; None when Talos does not report it."""
    try:
        out = await _run(talosconfig, "-n", node, "get", "nodestatus", "-o", "json", endpoint=node if direct else None)
    except TalosError:
        return None
    for obj in _json_stream(out):
        if (obj.get("metadata") or {}).get("id") in (hostname, None):
            ready = (obj.get("spec") or {}).get("nodeReady")
            return None if ready is None else bool(ready)
    return None


async def version(talosconfig: str, node: str, direct: bool = False) -> str | None:
    try:
        out = await _run(talosconfig, "-n", node, "version", "--short", endpoint=node if direct else None)
    except TalosError:
        return None
    m = re.search(r"v\d+\.\d+\.\d+\S*", out.split("Server:")[-1])
    return m.group(0) if m else None
