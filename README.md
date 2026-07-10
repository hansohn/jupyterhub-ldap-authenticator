<div align="center">
  <h3>jupyterhub-ldap-authenticator</h3>
  <p>LDAP Authenticator plugin for JupyterHub</p>
  <p>
    <!-- Build Status -->
    <a href="https://github.com/hansohn/jupyterhub-ldap-authenticator/actions/workflows/python.yml">
      <img src="https://img.shields.io/github/actions/workflow/status/hansohn/jupyterhub-ldap-authenticator/python.yml?branch=main&style=for-the-badge">
    </a>
    <!-- PyPI -->
    <a href="https://pypi.org/project/jupyterhub-ldap-authenticator/">
      <img src="https://img.shields.io/pypi/v/jupyterhub-ldap-authenticator.svg?style=for-the-badge">
    </a>
    <!-- License -->
    <a href="https://github.com/hansohn/jupyterhub-ldap-authenticator/blob/main/LICENSE">
      <img src="https://img.shields.io/github/license/hansohn/jupyterhub-ldap-authenticator.svg?style=for-the-badge">
    </a>
  </p>
</div>

### Contents

- [Description](#description)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Authentication strategy](#authentication-strategy)
  - [Server parameters](#server-parameters)
  - [Bind parameters](#bind-parameters)
  - [User and group parameters](#user-and-group-parameters)
  - [Home directory and auth state parameters](#home-directory-and-auth-state-parameters)
- [Examples](#examples)
- [Directory compatibility](#directory-compatibility)
- [Multi-factor authentication](#multi-factor-authentication)
- [Migrating from 0.x](#migrating-from-0x)
- [Development](#development)
- [License](#license)

### Description

An LDAP [Authenticator](https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html)
plugin for [JupyterHub](https://github.com/jupyterhub/jupyterhub), written with
Enterprise LDAP and Active Directory integration in mind. It supports:

- Multiple LDAP servers with configurable high-availability pooling (`server_pool_strategy`)
- Search-bind authentication using a service account, **or** direct-bind via `bind_dn_template`
- Modern TLS negotiation (`server_tls_strategy`: `before_bind` / `on_connect` / `insecure`)
- Group-based access control with `allowed_groups`, including recursive **nested group** resolution
- Automatic creation of a user's home directory at login
- Exposing selected LDAP attributes to JupyterHub as `auth_state`

> **Which LDAP authenticator should I use?**
> The JupyterHub organization maintains an official
> [`jupyterhub-ldapauthenticator`](https://github.com/jupyterhub/ldapauthenticator)
> package. This project is a **superset** of it — reach for this plugin when you
> need any of its distinguishing features: **automatic home-directory creation**,
> **multi-server failover pooling**, or **nested-group resolution**. For simpler
> deployments, the official package is an excellent choice.

### Installation

Install with pip:

```bash
pip install jupyterhub-ldap-authenticator
```

### Configuration

To enable `LDAPAuthenticator`, add the following to your JupyterHub config file and
extend it with the parameters below.

```python
c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
```

#### Authentication strategy

This plugin supports two authentication strategies:

- **Search-bind** (default): connect as a service account (`bind_user_dn` /
  `bind_user_password`), search the directory for the authenticating user, then
  verify their password. Requires `bind_user_dn`, `bind_user_password`,
  `user_search_base`, and `user_search_filter`.
- **Direct-bind**: bind to the server directly as the authenticating user using
  `bind_dn_template`, with no service account. Enabled automatically when
  `bind_dn_template` is set.

Fully worked configurations for each strategy are in [Examples](#examples).

#### Server parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `server_hosts` | List of names, IPs, or complete `scheme://host:port` URLs of the LDAP server(s). | _required_ |
| `server_port` | Port the LDAP server listens on. Typically 389 (cleartext) or 636 (secured). | `None` |
| `server_tls_strategy` | SSL/TLS strategy: `before_bind` (STARTTLS, recommended), `on_connect` (legacy LDAPS, port 636), or `insecure` (no TLS — cleartext). | `before_bind` |
| `server_tls_kwargs` | Keyword arguments passed to the ldap3 [`Tls`](https://ldap3.readthedocs.io/en/latest/ssltls.html) object. Ignored when `server_tls_strategy='insecure'`. | `{}` |
| `server_use_ssl` | **Deprecated since 1.0.** `True` is equivalent to `server_tls_strategy='on_connect'`. Use `server_tls_strategy` instead. | `False` |
| `server_connect_timeout` | Timeout, in seconds, when establishing a connection before raising an exception. | `None` |
| `server_receive_timeout` | Timeout, in seconds, for responses from an established connection before raising an exception. | `None` |
| `server_auto_referrals` | Whether ldap3 automatically follows server referrals. Disabled by default because chasing a referral re-sends the bind credentials to the referred server, which can leak them to a server chosen by the directory. Enable only if you require referral chasing and trust every server that may be referred. | `False` |
| `server_pool_strategy` | Pool HA strategy: `FIRST`, `ROUND_ROBIN`, or `RANDOM`. | `FIRST` |
| `server_pool_active` | If `True`, check server availability. Set to an integer for the maximum number of cycles to try before giving up. | `True` |
| `server_pool_exhaust` | If `True`, remove inactive servers from the pool. Set to an integer for the number of seconds an unreachable server is considered offline. | `False` |

> **⚠️ Certificate validation.** By default the ldap3 `Tls` object does **not** verify
> the server's certificate (`validate=ssl.CERT_NONE`), so `before_bind` and
> `on_connect` encrypt the connection but do **not** authenticate the server —
> leaving credentials exposed to man-in-the-middle attacks. When TLS is enabled
> without validation, the authenticator logs a warning at startup. **For production,
> enable verification against a CA bundle** via `server_tls_kwargs`:
>
> ```python
> import ssl
> c.LDAPAuthenticator.server_tls_kwargs = {
>     'validate': ssl.CERT_REQUIRED,
>     'ca_certs_file': '/etc/ssl/certs/ca-bundle.pem',
> }
> ```

#### Bind parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `bind_dn_template` | Template(s) for the full DN used to **direct-bind** as the authenticating user, bypassing the service-account search. `{username}` is substituted with the username. Accepts a string or a list of templates (tried in order). When set, the direct-bind strategy is used. | `None` |
| `bind_user_dn` | Service-account DN used for simple bind. Required for the search-bind strategy. | `None` |
| `bind_user_password` | Service-account password used for simple bind. Required for the search-bind strategy. | `None` |

```python
# direct-bind: a single template, or a list tried in order until one binds
c.LDAPAuthenticator.bind_dn_template = 'uid={username},ou=people,dc=example,dc=org'
c.LDAPAuthenticator.bind_dn_template = [
    'uid={username},ou=people,dc=example,dc=org',
    'uid={username},ou=developers,dc=example,dc=org',
]
```

#### User and group parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `user_search_base` | Location in the DIT where the user search starts. | _required (search-bind)_ |
| `user_search_filter` | LDAP filter validating that the user exists. `{username}` is substituted with the authenticating username. | _required (search-bind)_ |
| `user_membership_attribute` | LDAP attribute holding the user's group membership. | `memberOf` |
| `group_search_base` | Location in the DIT where the nested-group search starts. `{group}` is substituted with entries from `allowed_groups`. | _none_ |
| `group_search_filter` | LDAP filter returning members of groups in `allowed_groups`. `{group}` is substituted with the group DN. | _none_ |
| `allowed_groups` | List of group DNs a user must belong to in order to log in. If unset, group scoping is short-circuited and all authenticated users are allowed. | `None` |
| `allow_nested_groups` | Recursively search for members within nested groups of `allowed_groups`. | `False` |
| `username_pattern` | Regular expression a valid username must match. If unset, any username is allowed. | `None` |

#### Home directory and auth state parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `create_user_home_dir` | Create the user's home directory at login if it does not exist. | `False` |
| `create_user_home_dir_cmd` | Command (a list of strings) used to create the home directory; the username is appended as the final argument. | `['mkhomedir_helper']` on linux |
| `auth_state_attributes` | LDAP attributes to fetch and expose to JupyterHub as `auth_state`. Requires `Authenticator.enable_auth_state = True` to be persisted. | `[]` |

```python
c.LDAPAuthenticator.create_user_home_dir = True
c.LDAPAuthenticator.auth_state_attributes = ['mail', 'displayName']
```

> **Home-directory command.** The default `mkhomedir_helper` only creates a home
> directory for a user that already resolves as a local POSIX account (e.g. via
> SSSD/nslcd). In pure-LDAP deployments where users are **not** local system
> accounts, `mkhomedir_helper` fails and login returns a 500. In that case, use a
> command that also creates the account, for example:
>
> ```python
> # create the system user and its home directory
> c.LDAPAuthenticator.create_user_home_dir_cmd = ['useradd', '--create-home']
> ```
>
> The username is appended as the final argument. The command runs as the user
> the JupyterHub process runs as, so it must have permission to create accounts
> (typically root).

### Examples

#### FreeIPA Integration

```python
# freeipa example
c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
c.LDAPAuthenticator.server_hosts = ['ldaps://ldap1.example.com:636', 'ldaps://ldap2.example.com:636']
c.LDAPAuthenticator.bind_user_dn = 'uid=imauser,cn=users,cn=accounts,dc=example,dc=com'
c.LDAPAuthenticator.bind_user_password = 'imapassword'
c.LDAPAuthenticator.user_search_base = 'cn=users,cn=accounts,dc=example,dc=com'
c.LDAPAuthenticator.user_search_filter = '(&(objectClass=person)(uid={username}))'
c.LDAPAuthenticator.user_membership_attribute = 'memberOf'
c.LDAPAuthenticator.group_search_base = 'cn=groups,cn=accounts,dc=example,dc=com'
c.LDAPAuthenticator.group_search_filter = '(&(objectClass=ipausergroup)(memberOf={group}))'
c.LDAPAuthenticator.allowed_groups = ['cn=jupyterhub-users,cn=groups,cn=accounts,dc=example,dc=com']
c.LDAPAuthenticator.allow_nested_groups = True
c.LDAPAuthenticator.username_pattern = '[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?'
c.LDAPAuthenticator.create_user_home_dir = True
c.LDAPAuthenticator.create_user_home_dir_cmd = ['mkhomedir_helper']
```

#### Active Directory Integration

```python
# active directory example
c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
c.LDAPAuthenticator.server_hosts = ['ldaps://ldap1.example.com:636', 'ldaps://ldap2.example.com:636']
c.LDAPAuthenticator.bind_user_dn = 'CN=imauser,CN=Users,DC=example,DC=com'
c.LDAPAuthenticator.bind_user_password = 'imapassword'
c.LDAPAuthenticator.user_search_base = 'CN=Users,DC=example,DC=com'
c.LDAPAuthenticator.user_search_filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))'
c.LDAPAuthenticator.user_membership_attribute = 'memberOf'
c.LDAPAuthenticator.group_search_base = 'CN=Groups,DC=example,DC=com'
c.LDAPAuthenticator.group_search_filter = '(&(objectClass=group)(memberOf={group}))'
c.LDAPAuthenticator.allowed_groups = ['CN=jupyterhub-users,CN=Groups,DC=example,DC=com']
c.LDAPAuthenticator.allow_nested_groups = True
c.LDAPAuthenticator.username_pattern = '[a-zA-Z0-9_.][a-zA-Z0-9_.-]{8,20}[a-zA-Z0-9_.$-]?'
c.LDAPAuthenticator.create_user_home_dir = True
c.LDAPAuthenticator.create_user_home_dir_cmd = ['mkhomedir_helper']
```

#### OpenLDAP Integration (direct-bind)

Because OpenLDAP does not natively populate the `memberOf` attribute on user
objects, `allowed_groups` scoping is short-circuited below. This example also
uses the direct-bind strategy, avoiding a service account entirely:

```python
# openldap example
c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
c.LDAPAuthenticator.server_hosts = ['ldaps://ldap1.example.com:636', 'ldaps://ldap2.example.com:636']
c.LDAPAuthenticator.bind_dn_template = 'uid={username},ou=People,dc=example,dc=com'
c.LDAPAuthenticator.username_pattern = '[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?'
c.LDAPAuthenticator.create_user_home_dir = True
c.LDAPAuthenticator.create_user_home_dir_cmd = ['mkhomedir_helper']
```

### Directory compatibility

This authenticator uses an LDAP **simple bind** (username/DN + password) over an
optionally TLS-secured connection, and resolves groups from a `memberOf`-style
attribute. Any directory that supports those works. It does **not** implement
SASL, Kerberos/GSSAPI, NTLM, or client-certificate (EXTERNAL) bind mechanisms.

| Directory | Supported | Notes |
| --- | --- | --- |
| **Active Directory** | ✅ | Use a `sAMAccountName` search filter; `memberOf` is native. Modern/hardened AD often rejects cleartext simple bind — use `server_tls_strategy='before_bind'` or `'on_connect'`. |
| **FreeIPA / 389 Directory Server** | ✅ | `memberOf` is native. Supports OTP (see below). |
| **OpenLDAP** | ✅ | Requires the [`memberof` overlay](https://www.openldap.org/doc/admin24/overlays.html) for `allowed_groups`/nested groups; without it, authentication still works but group scoping does not. |
| **JumpCloud LDAP-as-a-Service** | ✅ | Standard simple bind + `memberOf`. |
| **Okta (LDAP Interface)** | ⚠️ | Works via Okta's LDAP Interface over LDAPS with Okta-specific base DNs. For native Okta, an OIDC authenticator is usually the better fit. |
| **Google Workspace (Secure LDAP)** | ⚠️ | Requires mutual TLS (client certificate) configured via `server_tls_kwargs` (`local_certificate_file` / `local_private_key_file`). |
| **Azure AD / Entra ID (native)** | ❌ | Cloud-only Entra ID exposes no LDAP endpoint at all — it speaks OIDC/SAML, so use an OAuth/OIDC authenticator ([`oauthenticator`](https://github.com/jupyterhub/oauthenticator)) instead. To use LDAP against an Entra tenant, add **Entra Domain Services** (Azure AD DS), a managed AD-compatible service that _does_ speak LDAP — then the Active Directory row applies. |

Rule of thumb: if the directory accepts an LDAP **simple bind over TLS** and
exposes a **`memberOf`-like attribute**, it is compatible. Kerberos-only realms
and proprietary APIs are not.

### Multi-factor authentication

This plugin does not implement MFA as a first-class feature — there is no
separate OTP field, challenge-response step, or push handling (JupyterHub's login
form is a single username/password step).

However, because the password field is passed through to the LDAP bind unchanged,
**"append your one-time code to your password" MFA works transparently** with any
directory that validates the appended code at bind time:

| MFA style | Works | How |
| --- | --- | --- |
| Password + OTP concatenation | ✅ | User enters `password123456`; the directory validates the trailing code during bind |
| FreeIPA OTP | ✅ | FreeIPA's documented `password+OTP` bind model |
| Okta LDAP Interface MFA | ✅ | Append a TOTP code, or literally append `push` for Okta Verify push |
| RADIUS-fronted LDAP | ✅ | Same concatenation model |
| Interactive challenge-response | ❌ | Would require a second login prompt |
| Push-only with nothing appended | ❌ | Unless the directory triggers/blocks on the push during the bind |

In other words, MFA is a property of the directory that this plugin's
pass-through bind preserves, rather than something the plugin performs itself.

### Migrating from 0.x

Version 1.0 is backward compatible — existing configurations continue to work.
Two changes are worth noting:

- `server_use_ssl` is **deprecated** in favor of `server_tls_strategy`. Setting
  `server_use_ssl = True` still works but now emits a warning and is translated to
  `server_tls_strategy = 'on_connect'`. Note the new default `server_tls_strategy`
  is `before_bind` (STARTTLS); if you relied on the previous plaintext default,
  set `server_tls_strategy = 'insecure'` explicitly.
- The authenticator is now `async`, requiring **JupyterHub >= 2.0** and **Python >= 3.10**.

### Development

This project uses a `Makefile` to drive common tasks. Run `make help` for the
full list.

```bash
make venv     # create a virtualenv and install dependencies
make lint     # run ruff (lint + format check) and mypy
make test     # run the pytest suite
make build    # build the sdist/wheel package
```

### License

[MIT](LICENSE)
