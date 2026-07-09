"""Demo JupyterHub config wiring in the LDAP authenticator.

Switch STRATEGY between 'search_bind' and 'direct_bind' to try each path.
Set ENABLE_GROUPS = True to require membership in an allowed group.
"""

import os

c = get_config()  # noqa: F821 (provided by jupyterhub at runtime)

STRATEGY = os.environ.get("LDAP_STRATEGY", "search_bind")
ENABLE_GROUPS = os.environ.get("LDAP_ENABLE_GROUPS", "false").lower() == "true"

c.JupyterHub.authenticator_class = "ldapauthenticator.LDAPAuthenticator"

# --- connection (plaintext ldap:// for the demo only) ---
c.LDAPAuthenticator.server_hosts = ["ldap://openldap:389"]
c.LDAPAuthenticator.server_tls_strategy = "insecure"

# --- strategy ---
if STRATEGY == "direct_bind":
    # bind directly as the user; no service account required
    c.LDAPAuthenticator.bind_dn_template = "uid={username},ou=people,dc=example,dc=org"
else:
    # search-bind: connect as a service account, find the user, then verify
    c.LDAPAuthenticator.bind_user_dn = "cn=admin,dc=example,dc=org"
    c.LDAPAuthenticator.bind_user_password = "admin"
    c.LDAPAuthenticator.user_search_base = "ou=people,dc=example,dc=org"
    c.LDAPAuthenticator.user_search_filter = "(uid={username})"

# --- optional group access control (requires the memberof overlay) ---
if ENABLE_GROUPS:
    c.LDAPAuthenticator.allowed_groups = ["cn=jupyterhub-users,ou=groups,dc=example,dc=org"]
    c.LDAPAuthenticator.allow_nested_groups = True
    c.LDAPAuthenticator.group_search_base = "ou=groups,dc=example,dc=org"
    c.LDAPAuthenticator.group_search_filter = (
        "(&(objectClass=groupOfUniqueNames)(memberOf={group}))"
    )

# --- expose LDAP attributes to auth_state ---
c.LDAPAuthenticator.auth_state_attributes = ["mail"]
c.Authenticator.enable_auth_state = True

# --- authorization: allow any successfully authenticated user (demo) ---
c.Authenticator.allow_all = True

# --- spawner: run single-user servers without needing real OS accounts ---
c.JupyterHub.spawner_class = "jupyterhub.spawner.SimpleLocalProcessSpawner"
c.SimpleLocalProcessSpawner.home_dir_template = "/tmp/{username}"

c.JupyterHub.ip = "0.0.0.0"
c.JupyterHub.port = 8000
