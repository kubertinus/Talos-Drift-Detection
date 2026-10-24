"""Webhook notifications (Slack, Mattermost, Teams workflows, or anything that takes JSON).

Each URL in NOTIFY_WEBHOOK_URLS gets a POST with `text` (a readable line, which chat tools show)
and the structured fields. Sending never blocks or fails the caller; errors are only logged.
"""
import asyncio
import json
import logging
import urllib.request
from datetime import datetime, timezone

from . import config

log = logging.getLogger("notify")
TIMEOUT = 10


def _post(url: str, payload: dict) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload, default=str).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (admin-configured URL)
        resp.read()


async def _deliver(payload: dict) -> None:
    for url in config.NOTIFY_WEBHOOK_URLS:
        try:
            await asyncio.to_thread(_post, url, payload)
        except Exception as e:
            log.warning("webhook %s failed: %s", url.split("?")[0], e)


def send(event: str, cluster: dict | None, text: str, **fields) -> None:
    """Queue a notification; a no-op when no webhook is configured or no event loop runs."""
    if not config.NOTIFY_WEBHOOK_URLS:
        return
    payload = {
        "text": f"[Talos Config Manager] {text}",
        "event": event,
        "cluster": cluster["name"] if cluster else None,
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **fields,
    }
    try:
        asyncio.get_running_loop().create_task(_deliver(payload))
    except RuntimeError:
        log.debug("no event loop; notification %s not sent", event)
