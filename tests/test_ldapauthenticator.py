"""Behavioral tests for LDAPAuthenticator against an in-memory LDAP fake."""

import asyncio
import ssl

import ldap3
import pytest

from ldapauthenticator import LDAPAuthenticator

from .conftest import FakeConnection, FakeDirectory

USER_BASE = "ou=people,dc=example,dc=org"
GROUP_BASE = "ou=groups,dc=example,dc=org"


def run(coro):
    return asyncio.run(coro)


def alice_directory(groups=None, extra_attributes=None, nested=None, referrals=0):
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
        referrals=referrals,
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


def test_search_bind_ignores_ad_referrals(make_authenticator):
    # regression for AD: searchResRef referral entries in the response must not
    # be counted as extra matches (issue #8 / PR #20)
    auth = make_authenticator(
        alice_directory(referrals=2),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


def test_search_bind_escapes_filter_injection(make_authenticator):
    # a username with LDAP filter metacharacters must be escaped, not injected
    # into the search filter verbatim
    captured = {}
    directory = alice_directory()
    orig_search = directory.search

    def spy(search_base, search_filter, search_scope, attributes):
        captured["filter"] = search_filter
        return orig_search(search_base, search_filter, search_scope, attributes)

    directory.search = spy
    auth = make_authenticator(
        directory,
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    run(auth.authenticate(None, {"username": "alice)(uid=*", "password": "secret"}))
    # the raw injection payload must not appear unescaped in the filter, and its
    # metacharacters must be present in escaped form
    assert ")(uid=*" not in captured["filter"]
    assert "\\28uid=\\2a" in captured["filter"]


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
# admin_groups (issue #18)
# ---------------------------------------------------------------------------


ADMIN_GROUP = "cn=jupyterhub-admins,ou=groups,dc=example,dc=org"


def test_admin_group_grants_admin_search_bind(make_authenticator):
    auth = make_authenticator(
        alice_directory(groups=[ADMIN_GROUP]),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        admin_groups=[ADMIN_GROUP],
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {"name": "alice", "admin": True}


def test_admin_group_grants_admin_direct_bind(make_authenticator):
    auth = make_authenticator(
        alice_directory(groups=[ADMIN_GROUP]),
        direct_bind=True,
        bind_dn_template="uid={username},ou=people,dc=example,dc=org",
        admin_groups=[ADMIN_GROUP],
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {"name": "alice", "admin": True}


def test_non_admin_user_gets_admin_false(make_authenticator):
    # a valid user not in any admin group is explicitly demoted (admin=False),
    # which lets the directory demote a user the static list can't
    auth = make_authenticator(
        alice_directory(groups=["cn=other,ou=groups,dc=example,dc=org"]),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        admin_groups=[ADMIN_GROUP],
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {"name": "alice", "admin": False}


def test_admin_via_nested_group(make_authenticator):
    child = "cn=child-admins,ou=groups,dc=example,dc=org"
    auth = make_authenticator(
        alice_directory(groups=[child], nested={ADMIN_GROUP: [child]}),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        group_search_base=GROUP_BASE,
        group_search_filter="(memberOf={group})",
        admin_groups=[ADMIN_GROUP],
        allow_nested_groups=True,
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {"name": "alice", "admin": True}


def test_admin_users_additive_with_admin_groups(make_authenticator):
    # a user not in any admin group but listed in the static admin_users stays
    # admin (admin_groups is additive, not authoritative)
    auth = make_authenticator(
        alice_directory(groups=["cn=other,ou=groups,dc=example,dc=org"]),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        admin_groups=[ADMIN_GROUP],
        admin_users={"alice"},
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {"name": "alice", "admin": True}


def test_admin_groups_unset_leaves_return_unchanged(make_authenticator):
    # backward compatibility: without admin_groups, the bare username is returned
    auth = make_authenticator(
        alice_directory(groups=[ADMIN_GROUP]),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


def test_admin_groups_combines_with_auth_state(make_authenticator):
    auth = make_authenticator(
        alice_directory(groups=[ADMIN_GROUP], extra_attributes={"mail": ["alice@example.org"]}),
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
        admin_groups=[ADMIN_GROUP],
        auth_state_attributes=["mail"],
    )
    result = run(auth.authenticate(None, {"username": "alice", "password": "secret"}))
    assert result == {
        "name": "alice",
        "auth_state": {"mail": ["alice@example.org"]},
        "admin": True,
    }


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


# ---------------------------------------------------------------------------
# security hardening: TLS validation warning and referral chasing
# ---------------------------------------------------------------------------


def test_tls_without_validation_warns():
    # TLS active but no cert validation -> one-time MITM warning path taken
    auth = LDAPAuthenticator()
    auth.server_tls_strategy = "before_bind"
    auth.create_ldap_server_obj("ldap.example.com")
    assert auth._insecure_tls_warned is True


def test_tls_with_validation_does_not_warn():
    auth = LDAPAuthenticator()
    auth.server_tls_strategy = "before_bind"
    auth.server_tls_kwargs = {"validate": ssl.CERT_REQUIRED}
    auth.create_ldap_server_obj("ldap.example.com")
    assert getattr(auth, "_insecure_tls_warned", False) is False


def test_insecure_strategy_does_not_warn_about_tls():
    auth = LDAPAuthenticator()
    auth.server_tls_strategy = "insecure"
    auth.create_ldap_server_obj("ldap.example.com")
    assert getattr(auth, "_insecure_tls_warned", False) is False


def test_auto_referrals_default_false():
    assert LDAPAuthenticator().server_auto_referrals is False


def test_ldap_connection_disables_referrals(monkeypatch):
    captured = {}

    class FakeConn:
        def __init__(self, *args, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    auth = LDAPAuthenticator()
    pool = auth.create_ldap_server_pool_obj()
    auth.ldap_connection(pool, "cn=svc,dc=example,dc=org", "pw")
    assert captured["auto_referrals"] is False
    assert captured["read_only"] is True


def test_server_use_ssl_deprecation_shim():
    auth = LDAPAuthenticator()
    auth.server_use_ssl = True
    assert auth.server_tls_strategy == "on_connect"


def test_ldaps_url_sets_on_connect():
    auth = LDAPAuthenticator()
    assert auth.validate_host("ldaps://ldap.example.com:636") is True
    assert auth.server_tls_strategy == "on_connect"


@pytest.mark.parametrize(
    "host",
    [
        "ldap.example.com",  # FQDN
        "localhost",  # single-label hostname
        "openldap",  # container/service name
        "10.0.0.1",  # ipv4
        "ldap://openldap:389",  # url with single-label host
        "ldaps://ldap.example.com:636",  # url with FQDN
    ],
)
def test_validate_host_accepts_valid_hosts(host):
    assert LDAPAuthenticator().validate_host(host) is True


@pytest.mark.parametrize("host", ["bad!!host", "ldap://:389", "has space"])
def test_validate_host_rejects_invalid_hosts(host):
    assert LDAPAuthenticator().validate_host(host) is False


# ---------------------------------------------------------------------------
# server pool assembly and home-dir command
# ---------------------------------------------------------------------------


def test_multi_host_pool_assembly():
    auth = LDAPAuthenticator()
    pool = auth.create_ldap_server_pool_obj()
    for host in ["ldap1.example.com", "ldap2.example.com"]:
        pool.add(auth.create_ldap_server_obj(host))
    assert len(pool.servers) == 2


def test_build_server_pool_skips_invalid_host():
    # regression: a malformed host must not drop subsequent valid hosts (was a
    # `break` that aborted the whole loop instead of skipping the bad entry)
    auth = LDAPAuthenticator()
    auth.server_hosts = ["bad!!host", "ldap1.example.com", "ldap2.example.com"]
    pool, conn_servers = auth._build_server_pool()
    assert conn_servers == ["ldap1.example.com", "ldap2.example.com"]
    assert len(pool.servers) == 2


def test_authenticate_survives_leading_invalid_host(make_authenticator):
    # end-to-end: an invalid first host would previously drop the valid one and
    # fail auth entirely
    auth = make_authenticator(
        alice_directory(),
        server_hosts=["bad!!host", "ldap.example.com"],
        bind_user_dn="cn=svc,dc=example,dc=org",
        bind_user_password="svcpass",
        user_search_base=USER_BASE,
        user_search_filter="(uid={username})",
    )
    assert run(auth.authenticate(None, {"username": "alice", "password": "secret"})) == "alice"


def test_nested_groups_cycle_terminates(make_authenticator):
    # regression: cyclic group nesting (parent <-> child) must not recurse forever
    parent = "cn=parent,ou=groups,dc=example,dc=org"
    child = "cn=child,ou=groups,dc=example,dc=org"
    auth = make_authenticator(
        alice_directory(groups=[child], nested={parent: [child], child: [parent]}),
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
