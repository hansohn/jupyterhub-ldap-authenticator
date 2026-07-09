"""Behavioral tests for LDAPAuthenticator against an in-memory LDAP fake."""

import asyncio

import ldap3
import pytest

from ldapauthenticator import LDAPAuthenticator

from .conftest import FakeConnection, FakeDirectory

USER_BASE = "ou=people,dc=example,dc=org"
GROUP_BASE = "ou=groups,dc=example,dc=org"


def run(coro):
    return asyncio.run(coro)


def alice_directory(groups=None, extra_attributes=None, nested=None):
    attributes = {"memberOf": groups or []}
    if extra_attributes:
        attributes.update(extra_attributes)
    return FakeDirectory(
        users={
            "alice": {
                "dn": "uid=alice,ou=people,dc=example,dc=org",
                "password": "secret",
                "attributes": attributes,
            }
        },
        nested=nested,
        user_search_base=USER_BASE,
        group_search_base=GROUP_BASE,
    )


# ---------------------------------------------------------------------------
# search-bind strategy
# ---------------------------------------------------------------------------


def test_search_bind_success(make_authenticator):
    auth = make_authenticator(
        alice_directory(),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


def test_search_bind_wrong_password(make_authenticator):
    auth = make_authenticator(
        alice_directory(),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "wrong"})) is None


def test_search_bind_requires_service_account(make_authenticator):
    auth = make_authenticator(
        alice_directory(),
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    # no bind_user_dn configured and no bind_dn_template -> cannot proceed
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) is None


def test_group_allowed(make_authenticator):
    auth = make_authenticator(
        alice_directory(groups=["cn=jupyter,ou=groups,dc=example,dc=org"]),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        allowed_groups=["cn=jupyter,ou=groups,dc=example,dc=org"],
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


def test_group_denied(make_authenticator):
    auth = make_authenticator(
        alice_directory(groups=["cn=other,ou=groups,dc=example,dc=org"]),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        allowed_groups=["cn=jupyter,ou=groups,dc=example,dc=org"],
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) is None


def test_nested_groups_allowed(make_authenticator):
    # alice is a member of the child group; the parent is allowed and nested
    # resolution should expand parent -> child.
    parent = "cn=parent,ou=groups,dc=example,dc=org"
    child = "cn=child,ou=groups,dc=example,dc=org"
    auth = make_authenticator(
        alice_directory(groups=[child], nested={parent: [child]}),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        group_search_base=GROUP_BASE,
        group_search_filter="(memberOf={group})",
        allowed_groups=[parent],
        allow_nested_groups=True,
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


# ---------------------------------------------------------------------------
# direct-bind strategy (bind_dn_template)
# ---------------------------------------------------------------------------


def test_direct_bind_success(make_authenticator):
    auth = make_authenticator(
        alice_directory(),
        direct_bind=True,
        bind_dn_template="uid={username},ou=people,dc=example,dc=org",
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


def test_direct_bind_wrong_password(make_authenticator):
    auth = make_authenticator(
        alice_directory(),
        direct_bind=True,
        bind_dn_template="uid={username},ou=people,dc=example,dc=org",
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "nope"})) is None


def test_direct_bind_multiple_templates(make_authenticator):
    # first template does not match the user's dn; second one does
    auth = make_authenticator(
        alice_directory(),
        direct_bind=True,
        bind_dn_template=[
            "uid={username},ou=developers,dc=example,dc=org",
            "uid={username},ou=people,dc=example,dc=org",
        ],
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


def test_direct_bind_group_denied(make_authenticator):
    auth = make_authenticator(
        alice_directory(groups=["cn=other,ou=groups,dc=example,dc=org"]),
        direct_bind=True,
        bind_dn_template="uid={username},ou=people,dc=example,dc=org",
        allowed_groups=["cn=jupyter,ou=groups,dc=example,dc=org"],
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) is None


# ---------------------------------------------------------------------------
# auth_state
# ---------------------------------------------------------------------------


def test_auth_state_search_bind(make_authenticator):
    auth = make_authenticator(
        alice_directory(extra_attributes={"mail": ["alice@example.org"]}),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        auth_state_attributes=["mail"],
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {"name": "alice", "auth_state": {"mail": ["alice@example.org"]}}


def test_auth_state_direct_bind(make_authenticator):
    auth = make_authenticator(
        alice_directory(extra_attributes={"mail": ["alice@example.org"]}),
        direct_bind=True,
        bind_dn_template="uid={username},ou=people,dc=example,dc=org",
        auth_state_attributes=["mail"],
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {"name": "alice", "auth_state": {"mail": ["alice@example.org"]}}


# ---------------------------------------------------------------------------
# input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "username,password",
    [
        ("al/ice", "secret"),  # slash not allowed
        ("alice", ""),  # empty password
        ("alice", "   "),  # whitespace password
    ],
)
def test_invalid_credentials_rejected(make_authenticator, username, password):
    auth = make_authenticator(
        alice_directory(),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    assert run(auth.authenticate(None, {"username": username, "password": password})) is None


def test_username_pattern_enforced(make_authenticator):
    auth = make_authenticator(
        alice_directory(),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        username_pattern="^[a-z]+$",
    )
    assert run(auth.authenticate(None, {"username": "b0b", "password": "secret"})) is None


# ---------------------------------------------------------------------------
# TLS strategy wiring and deprecation shim (no network / no mock needed)
# ---------------------------------------------------------------------------


def test_tls_strategy_on_connect_sets_ssl():
    auth = LDAPAuthenticator()
    auth.server_tls_strategy = "on_connect"
    server = auth.create_ldap_server_obj("ldap.example.com")
    assert server.ssl is True


def test_tls_strategy_before_bind_builds_tls():
    auth = LDAPAuthenticator()
    auth.server_tls_strategy = "before_bind"
    server = auth.create_ldap_server_obj("ldap.example.com")
    assert server.ssl is False
    assert server.tls is not None


def test_tls_strategy_insecure_no_tls():
    auth = LDAPAuthenticator()
    auth.server_tls_strategy = "insecure"
    server = auth.create_ldap_server_obj("ldap.example.com")
    assert server.ssl is False
    assert server.tls is None


def test_server_use_ssl_deprecation_shim():
    auth = LDAPAuthenticator()
    auth.server_use_ssl = True
    assert auth.server_tls_strategy == "on_connect"


def test_ldaps_url_sets_on_connect():
    auth = LDAPAuthenticator()
    assert auth.validate_host("ldaps://ldap.example.com:636") is True
    assert auth.server_tls_strategy == "on_connect"


# ---------------------------------------------------------------------------
# server pool assembly and home-dir command
# ---------------------------------------------------------------------------


def test_multi_host_pool_assembly():
    auth = LDAPAuthenticator()
    pool = auth.create_ldap_server_pool_obj()
    for host in ["ldap1.example.com", "ldap2.example.com"]:
        pool.add(auth.create_ldap_server_obj(host))
    assert len(pool.servers) == 2


def test_default_home_dir_cmd_on_linux(monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    auth = LDAPAuthenticator()
    assert auth.create_user_home_dir_cmd == ["mkhomedir_helper"]


def test_search_response_helpers():
    # _build_auth_response returns a bare username when no auth_state configured
    auth = LDAPAuthenticator()
    assert auth._build_auth_response("alice", {"mail": ["a@b.c"]}) == "alice"
    auth.auth_state_attributes = ["mail"]
    assert auth._build_auth_response("alice", {"mail": ["a@b.c"]}) == {
        "name": "alice",
        "auth_state": {"mail": ["a@b.c"]},
    }


def test_fake_connection_smoke():
    # sanity check the test double itself
    directory = alice_directory()
    conn = FakeConnection(directory)
    assert conn.bind() is True
    assert conn.rebind(user="uid=alice,ou=people,dc=example,dc=org", password="secret") is True
    conn.search(
        search_base="uid=alice,ou=people,dc=example,dc=org",
        search_scope=ldap3.BASE,
        attributes=["memberOf"],
    )
    assert conn.response[0]["dn"] == "uid=alice,ou=people,dc=example,dc=org"
