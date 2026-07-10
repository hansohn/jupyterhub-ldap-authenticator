"""Shared pytest fixtures and an in-memory LDAP fake.

The fake intercepts the single network boundary in the authenticator
(`LDAPAuthenticator.ldap_connection`) so that the full authenticate() logic —
validation, host/pool assembly, search-bind vs direct-bind branching, group
membership, nested groups, and auth_state — runs against an in-memory directory
without a live LDAP server.
"""

import ldap3
import pytest

from ldapauthenticator import LDAPAuthenticator


class FakeDirectory:
    """A tiny in-memory directory used to drive FakeConnection responses."""

    def __init__(
        self,
        users=None,
        nested=None,
        user_search_base=None,
        group_search_base=None,
        referrals=0,
    ):
        # users: {username: {"dn": str, "password": str, "attributes": {..}}}
        self.users = users or {}
        # nested: {group_dn: [child_group_dn, ...]}
        self.nested = nested or {}
        self.user_search_base = user_search_base
        self.group_search_base = group_search_base
        # number of Active Directory searchResRef referral entries to include
        # alongside real results in user searches
        self.referrals = referrals

    def check_password(self, dn, password):
        entry = self._entry_by_dn(dn)
        return bool(entry and entry.get("password") == password)

    def _entry_by_dn(self, dn):
        for user in self.users.values():
            if user["dn"] == dn:
                return user
        return None

    @staticmethod
    def _project(attributes, requested):
        # Always return an "attributes" mapping with every requested key present.
        if not requested:
            return {}
        return {key: attributes.get(key, []) for key in requested}

    @staticmethod
    def _referrals(count):
        # ldap3 represents AD referral entries as dicts with a searchResRef type
        return [
            {"type": "searchResRef", "uri": [f"ldap://ref{i}.example.org"]} for i in range(count)
        ]

    def search(self, search_base, search_filter, search_scope, attributes):
        # BASE scope: read a single entry directly by its dn
        if search_scope == ldap3.BASE:
            entry = self._entry_by_dn(search_base)
            if not entry:
                return []
            return [
                {
                    "type": "searchResEntry",
                    "dn": entry["dn"],
                    "attributes": self._project(entry.get("attributes", {}), attributes),
                }
            ]
        # nested group search under the group_search_base
        if self.group_search_base and search_base == self.group_search_base:
            children = []
            for group_dn, kids in self.nested.items():
                if group_dn in (search_filter or ""):
                    children.extend({"type": "searchResEntry", "dn": kid} for kid in kids)
            return children
        # user search (SUBTREE): match the entry whose username is in the filter
        for username, user in self.users.items():
            if username in (search_filter or ""):
                return [
                    {
                        "type": "searchResEntry",
                        "dn": user["dn"],
                        "attributes": self._project(user.get("attributes", {}), attributes),
                    },
                    *self._referrals(self.referrals),
                ]
        return []


class FakeConnection:
    """Stand-in for ldap3.Connection driven by a FakeDirectory."""

    def __init__(self, directory, bind_result=True):
        self._dir = directory
        self._bind_result = bind_result
        # ldap3 sets Connection.bound after a successful auto_bind; mirror that
        self.bound = bind_result
        self.response = []
        self.unbound = False

    def bind(self):
        return self._bind_result

    def rebind(self, user=None, password=None):
        return self._dir.check_password(user, password)

    def unbind(self):
        self.unbound = True
        return True

    def search(
        self,
        search_base=None,
        search_filter=None,
        search_scope=None,
        attributes=None,
        paged_size=None,
    ):
        self.response = self._dir.search(search_base, search_filter, search_scope, attributes)
        return bool(self.response)


@pytest.fixture
def make_authenticator(monkeypatch):
    """Build an LDAPAuthenticator with its ldap_connection patched to the fake."""

    def _make(directory, bind_result=True, direct_bind=False, **config):
        auth = LDAPAuthenticator()
        auth.server_hosts = ["ldap.example.com"]
        for key, value in config.items():
            setattr(auth, key, value)

        def fake_ldap_connection(server_pool, username, password):
            if direct_bind:
                # direct bind: a wrong password means the bind fails (no connection)
                if not directory.check_password(username, password):
                    return None
                return FakeConnection(directory, bind_result=True)
            return FakeConnection(directory, bind_result=bind_result)

        monkeypatch.setattr(auth, "ldap_connection", fake_ldap_connection)
        return auth

    return _make
