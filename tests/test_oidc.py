import pytest

from app import config, oidc


def test_roles_from_realm_client_and_groups(monkeypatch):
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", "talos-drift")
    access = {
        "realm_access": {"roles": ["offline_access", "infra"]},
        "resource_access": {"talos-drift": {"roles": ["viewer"]}, "other": {"roles": ["admin"]}},
    }
    roles, groups = oidc.roles_and_groups({"groups": ["/platform/ops"]}, access)
    assert roles == {"offline_access", "infra", "viewer"}
    assert groups == {"platform/ops"}


@pytest.mark.parametrize(
    "allowed_roles, allowed_groups, roles, groups, ok",
    [
        ([], [], set(), set(), True),  # no restriction
        (["viewer"], [], {"viewer"}, set(), True),
        (["viewer"], [], {"admin"}, set(), False),  # client role of another client doesn't count
        ([], ["/platform/ops"], set(), {"platform/ops"}, True),
        ([], ["platform/ops"], set(), {"platform"}, False),
    ],
)
def test_is_allowed(monkeypatch, allowed_roles, allowed_groups, roles, groups, ok):
    monkeypatch.setattr(config, "OIDC_ALLOWED_ROLES", allowed_roles)
    monkeypatch.setattr(config, "OIDC_ALLOWED_GROUPS", allowed_groups)
    assert oidc.is_allowed(roles, groups) is ok
