"""Who did what.

Per cluster, `<cluster>.audit` keeps the patch rollouts (with patch text and before-state, for
rollbacks). The global `activity` log keeps every action that changes something: settings,
files, patches, clusters, certificates, logins. Each activity entry is also written to the
container log as one JSON line (logger "audit"), for a central log system.
"""
import json
import logging
import secrets
from datetime import datetime, timezone

from . import store
from .store import key

MAX_ENTRIES = 500
MAX_ACTIVITY = 5000
ACTIVITY = "activity"
log = logging.getLogger("audit")


def entries(cid: str) -> list[dict]:
    """Newest first."""
    return list(reversed(store._load(key(cid, "audit"), [])))


def add(cid: str, entry: dict) -> None:
    log_ = store._load(key(cid, "audit"), [])
    log_.append(entry)
    store._save(key(cid, "audit"), log_[-MAX_ENTRIES:])


def get(cid: str, entry_id: str) -> dict | None:
    return next((e for e in entries(cid) if e.get("id") == entry_id), None)


def record(actor: dict, action: str, cluster: dict | None = None, **details) -> None:
    """Add one entry to the activity log. `details` must not contain secrets or file contents."""
    entry = {
        "id": secrets.token_hex(6),
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": actor,
        "action": action,
        "cluster": {"id": cluster["id"], "name": cluster["name"]} if cluster else None,
        "details": details,
    }
    activity = store._load(ACTIVITY, [])
    activity.append(entry)
    store._save(ACTIVITY, activity[-MAX_ACTIVITY:])
    log.info(json.dumps({"audit": entry}, default=str, sort_keys=True))


def activity(cluster_id: str = "", user: str = "", limit: int = 500) -> list[dict]:
    """Newest first, optionally only one cluster and/or one user (actor id)."""
    out = []
    for e in reversed(store._load(ACTIVITY, [])):
        if cluster_id and (e.get("cluster") or {}).get("id") != cluster_id:
            continue
        if user and e["actor"].get("id") != user:
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


def users() -> list[dict]:
    """Distinct actors in the activity log, for the filter."""
    seen = {}
    for e in store._load(ACTIVITY, []):
        seen[e["actor"].get("id")] = e["actor"]
    return sorted(seen.values(), key=lambda a: (a.get("name") or a.get("id") or "").lower())


def changes(old: dict, new: dict) -> dict:
    """{field: {"old": ..., "new": ...}} for the fields that differ."""
    return {k: {"old": old.get(k), "new": new.get(k)} for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)}
