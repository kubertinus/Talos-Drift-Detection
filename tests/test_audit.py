import json
import logging

import pytest

from app import audit, auth, vault
from app.vault import Vault

JAN = {"id": "oidc:1234", "username": "jjansen", "name": "Jan Jansen", "method": "oidc", "ip": "10.0.0.5"}
PIET = {"id": "oidc:5678", "username": "piet", "name": "Piet", "method": "oidc", "ip": "10.0.0.6"}
ADMIN = {"id": "admin", "username": "admin", "name": "admin", "method": "password", "ip": "10.0.0.7"}


@pytest.fixture(autouse=True)
def v(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "_vault", Vault("x" * 40, tmp_path / "data", tmp_path / "tmp"))


def test_record_filter_and_users(caplog):
    prod, lab = {"id": "prod-1", "name": "prod"}, {"id": "lab-1", "name": "lab"}
    with caplog.at_level(logging.INFO, logger="audit"):
        audit.record(JAN, "settings.scan", prod, **audit.changes({"scan_interval": 900}, {"scan_interval": 300}))
        audit.record(PIET, "file.upload", lab, file="worker.yaml", sha256="abc")
        audit.record(JAN, "login", method="oidc")
    assert [e["action"] for e in audit.activity()] == ["login", "file.upload", "settings.scan"]
    assert [e["action"] for e in audit.activity(cluster_id="prod-1")] == ["settings.scan"]
    assert [e["action"] for e in audit.activity(user="oidc:5678")] == ["file.upload"]
    assert audit.activity()[2]["details"] == {"scan_interval": {"old": 900, "new": 300}}
    assert [u["id"] for u in audit.users()] == ["oidc:1234", "oidc:5678"]
    line = json.loads(caplog.records[1].getMessage())["audit"]
    assert line["actor"]["username"] == "piet" and line["cluster"]["name"] == "lab"


def test_changes_only_lists_differences():
    assert audit.changes({"a": 1, "b": [1]}, {"a": 1, "b": [1, 2], "c": "x"}) == {
        "b": {"old": [1], "new": [1, 2]}, "c": {"old": None, "new": "x"}}


def test_actor_label():
    assert auth.actor_label(JAN) == "Jan Jansen (jjansen · oidc)"
    assert auth.actor_label({**JAN, "username": "Jan Jansen"}) == "Jan Jansen (oidc)"
    assert auth.actor_label(ADMIN) == "admin (password)"
