"""Normalise Talos machine configs, mask secrets and compute drift."""
import difflib
import hashlib
import json
import re
from collections import Counter
from functools import lru_cache

import yaml

# Only the values that legitimately differ per node; everything around them
# (MTU, routes, VIPs, ...) is still compared.
DEFAULT_IGNORE = [
    "machine.network.hostname",
    "machine.network.interfaces[*].addresses",
    "machine.install.disk",
    "HostnameConfig.hostname",
    "LinkConfig[*].addresses",
]

# Known secret paths in the v1alpha1 document. On top of these, any key that
# ends in key/token/secret is masked as well.
SECRET_PATHS = {
    "machine.token",
    "machine.ca.key",
    "cluster.token",
    "cluster.secret",
    "cluster.ca.key",
    "cluster.aggregatorCA.key",
    "cluster.serviceAccount.key",
    "cluster.etcd.ca.key",
    "cluster.secretboxEncryptionSecret",
    "cluster.aescbcEncryptionSecret",
}
SECRET_SUFFIXES = ("key", "token", "secret")


def _doc_key(doc: dict) -> str:
    """'' for the main v1alpha1 document, Kind or Kind[name] for the others."""
    kind = doc.get("kind")
    if not kind:
        return ""
    name = doc.get("name")
    return f"{kind}[{name}]" if name else kind


def _drop_empty(node):
    """Treat null, "" and empty maps/lists as absent: talosctl adds or strips them when re-serialising
    (Talos itself reads all of these as "not set")."""
    if isinstance(node, dict):
        out = {k: _drop_empty(v) for k, v in node.items()}
        return {k: v for k, v in out.items() if v not in (None, "", {}, [])}
    if isinstance(node, list):
        return [_drop_empty(v) for v in node]
    return node


def parse_config(text: str) -> dict[str, dict]:
    """Parse a (multi-document) machine config into {doc_key: doc}."""
    docs = {}
    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict):
            continue
        docs[_doc_key(doc)] = _drop_empty(doc)
    return docs


def _join(prefix: str, key) -> str:
    if isinstance(key, int):
        return f"{prefix}[{key}]"
    return f"{prefix}.{key}" if prefix else str(key)


def _is_secret(path: str, key) -> bool:
    if path in SECRET_PATHS:
        return True
    return isinstance(key, str) and key.lower().endswith(SECRET_SUFFIXES)


def mask_value(value) -> str:
    digest = hashlib.sha256(str(value).encode()).hexdigest()[:8]
    return f"***sha256:{digest}"


def mask(node, path: str = ""):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            p = _join(path, k)
            if _is_secret(p, k) and isinstance(v, str) and v:
                out[k] = mask_value(v)
            else:
                out[k] = mask(v, p)
        return out
    if isinstance(node, list):
        return [mask(v, _join(path, i)) for i, v in enumerate(node)]
    return node


def mask_docs(docs: dict[str, dict]) -> dict[str, dict]:
    return {k: mask(d, k) if k else mask(d) for k, d in docs.items()}


@lru_cache(maxsize=1024)
def _pattern(pattern: str) -> re.Pattern:
    """Compile an ignore pattern.

    `*` matches within one path segment, `[*]` matches any list index or
    document name, `**` matches across segments. Everything else is literal,
    so `Layer2VIPConfig[10.0.0.1]` matches exactly that document.
    """
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("[*]", i):
            out.append(r"\[[^\]]*\]")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append(r"[^.\[\]]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def _ancestors(path: str) -> list[str]:
    """'a.b[0].c' -> ['a.b[0].c', 'a.b[0]', 'a.b', 'a']; dots inside [...] don't split."""
    cuts, depth = [], 0
    for i, ch in enumerate(path):
        if ch == "[":
            if depth == 0 and i > 0:
                cuts.append(i)
            depth += 1
        elif ch == "]":
            depth -= 1
        elif ch == "." and depth == 0:
            cuts.append(i)
    return [path] + [path[:c] for c in reversed(cuts)]


def matching_rule(path: str, patterns: list[str]) -> str | None:
    """The pattern that ignores this path (directly or via an ancestor), if any."""
    for candidate in _ancestors(path):
        for pat in patterns:
            if _pattern(pat).fullmatch(candidate):
                return pat
    return None


def is_ignored(path: str, patterns: list[str]) -> bool:
    return matching_rule(path, patterns) is not None


def _prune(node, path: str, patterns: list[str]):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            p = _join(path, k)
            if is_ignored(p, patterns):
                continue
            pruned = _prune(v, p, patterns)
            # Drop containers that only held ignored keys, so they don't show up as drift.
            if v and isinstance(v, (dict, list)) and not pruned:
                continue
            out[k] = pruned
        return out
    if isinstance(node, list):
        return [_prune(v, _join(path, i), patterns) for i, v in enumerate(node)]
    return node


def prune_docs(docs: dict[str, dict], patterns: list[str]) -> dict[str, dict]:
    return {k: _prune(d, k, patterns) for k, d in docs.items() if not (k and is_ignored(k, patterns))}


# Identify a document via its path already; listing them per leaf is noise.
_DOC_HEADER = ("apiVersion", "kind", "name")


def _leaves(node, path: str, is_doc: bool = False):
    """Yield (path, value) for every leaf, so whole added/removed blocks can be ignored per field."""
    if isinstance(node, dict) and node:
        for k, v in node.items():
            if not (is_doc and k in _DOC_HEADER):
                yield from _leaves(v, _join(path, k))
    elif isinstance(node, list) and node:
        for i, v in enumerate(node):
            yield from _leaves(v, _join(path, i))
    else:
        yield path, node


def _one_sided(kind: str, value, path: str, out: list, is_doc: bool):
    for p, v in _leaves(value, path, is_doc):
        out.append({"path": p, "type": kind, "baseline": v if kind == "removed" else None,
                    "actual": v if kind == "added" else None})


def _compare(base, actual, path: str, out: list):
    if isinstance(base, dict) and isinstance(actual, dict):
        for k in sorted(set(base) | set(actual), key=str):
            p = _join(path, k)
            is_doc = path == "" and k != ""
            if k not in actual:
                _one_sided("removed", base[k], p, out, is_doc)
            elif k not in base:
                _one_sided("added", actual[k], p, out, is_doc)
            else:
                _compare(base[k], actual[k], p, out)
    elif isinstance(base, list) and isinstance(actual, list):
        for i in range(max(len(base), len(actual))):
            p = _join(path, i)
            if i >= len(actual):
                _one_sided("removed", base[i], p, out, False)
            elif i >= len(base):
                _one_sided("added", actual[i], p, out, False)
            else:
                _compare(base[i], actual[i], p, out)
    elif base != actual:
        out.append({"path": path, "type": "changed", "baseline": base, "actual": actual})


def to_yaml(docs: dict[str, dict]) -> str:
    return yaml.safe_dump_all([docs[k] for k in sorted(docs)], sort_keys=True, default_flow_style=False)


def compute(baseline_text: str, actual_text: str, ignore: list[str]) -> dict:
    """Compare a node's config with the role baseline.

    Both sides are masked before comparing; identical secrets hash the same,
    so a changed secret still shows up as drift without revealing its value.
    """
    base = mask_docs(parse_config(baseline_text))
    actual = mask_docs(parse_config(actual_text))
    found: list[dict] = []
    _compare(base, actual, "", found)
    changes, ignored = [], []
    for c in found:
        rule = matching_rule(c["path"], ignore)
        if rule:
            ignored.append({**c, "rule": rule})
        else:
            changes.append(c)
    base_yaml = to_yaml(prune_docs(base, ignore))
    actual_yaml = to_yaml(prune_docs(actual, ignore))
    diff = "".join(
        difflib.unified_diff(
            base_yaml.splitlines(keepends=True),
            actual_yaml.splitlines(keepends=True),
            fromfile="baseline",
            tofile="actual",
            n=4,
        )
    )
    return {"changes": changes, "ignored": ignored, "diff": diff}


def vips(docs: dict[str, dict]) -> set[str]:
    """Shared virtual IPs defined in a config; these float between nodes."""
    found = {d["name"] for k, d in docs.items() if k.split("[")[0].endswith("VIPConfig") and d.get("name")}
    network = (docs.get("", {}).get("machine") or {}).get("network") or {}
    for iface in network.get("interfaces") or []:
        for item in [iface, *(iface.get("vlans") or [])]:
            ip = (item.get("vip") or {}).get("ip")
            if ip:
                found.add(ip)
    return found


def signature(changes: list[dict]) -> str:
    payload = json.dumps([(c["path"], c["type"], c["actual"]) for c in changes], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def shape(changes: list[dict]) -> str:
    """Which paths drift, ignoring the values (those are often per node, e.g. IPs)."""
    payload = json.dumps(sorted((c["path"], c["type"]) for c in changes))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def mark_outliers(nodes: list[dict]) -> None:
    """Flag nodes whose drifting paths differ from a strict majority of their role."""
    for role in ("controlplane", "worker"):
        group = [n for n in nodes if n.get("role") == role and n.get("shape")]
        common, count = Counter(n["shape"] for n in group).most_common(1)[0] if group else (None, 0)
        has_majority = len(group) >= 3 and count * 2 > len(group)
        for n in group:
            n["outlier"] = has_majority and n["shape"] != common
