<div align="center">
  <h3>jupyterhub-ldap-authenticator</h3>
  <p>LDAP Authenticator plugin for JupyterHub</p>
  <p>
    <!-- Build Status -->
    <a href="https://github.com/hansohn/jupyterhub-ldap-authenticator/actions/workflows/python.yml">
      <img src="https://img.shields.io/github/actions/workflow/status/hansohn/jupyterhub-ldap-authenticator/python.yml?branch=master&style=for-the-badge">
    </a>
    <!-- PyPI -->
    <a href="https://pypi.org/project/jupyterhub-ldap-authenticator/">
      <img src="https://img.shields.io/pypi/v/jupyterhub-ldap-authenticator.svg?style=for-the-badge">
    </a>
    <!-- License -->
    <a href="https://github.com/hansohn/jupyterhub-ldap-authenticator/blob/master/LICENSE">
      <img src="https://img.shields.io/github/license/hansohn/jupyterhub-ldap-authenticator.svg?style=for-the-badge">
    </a>
    <!-- LinkedIn -->
    <a href="https://linkedin.com/in/ryanhansohn">
      <img src="https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555">
    </a>
  </p>
</div>

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

#### Server parameters

<dl>
  <dt>LDAPAuthenticator.server_hosts</dt>
  <dd>List of Names, IPs, or the complete URLs in the scheme://hostname:hostport format of the server (required).</dd>
</dl>

```python
# example - list of complete urls
c.LDAPAuthenticator.server_hosts = ['ldaps://ldap1.example.com:636', 'ldaps://ldap2.example.com:636']

# example - list of names
c.LDAPAuthenticator.server_hosts = ['ldap1.example.com', 'ldap2.example.com']

# example - list of ips
c.LDAPAuthenticator.server_hosts = ['10.0.0.1', '10.0.0.2']
```

<dl>
  <dt>LDAPAuthenticator.server_port</dt>
  <dd>The port where the LDAP server is listening. Typically 389, for a cleartext connection, and 636 for a secured connection (defaults to None).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.server_port = 636
```

<dl>
  <dt>LDAPAuthenticator.server_tls_strategy</dt>
  <dd>Strategy used to establish a SSL/TLS connection to the LDAP server (defaults to 'before_bind').
  <ul>
    <li><code>before_bind</code>: upgrade the connection to SSL/TLS before binding (STARTTLS). Modern, recommended.</li>
    <li><code>on_connect</code>: establish SSL/TLS directly on connect (legacy LDAPS, typically port 636).</li>
    <li><code>insecure</code>: do not use SSL/TLS. Credentials are sent in cleartext; only for trusted networks or testing.</li>
  </ul></dd>
</dl>

```python
# example
c.LDAPAuthenticator.server_tls_strategy = 'before_bind'
```

<dl>
  <dt>LDAPAuthenticator.server_tls_kwargs</dt>
  <dd>Dictionary of keyword arguments passed to the ldap3 <code>Tls</code> object, influencing encrypted connections. Ignored when <code>server_tls_strategy='insecure'</code>. See the <a href="https://ldap3.readthedocs.io/en/latest/ssltls.html">ldap3 documentation</a> for details.</dd>
</dl>

> **Certificate validation.** By default the underlying ldap3 `Tls` object does
> **not** verify the server's certificate (`validate=ssl.CERT_NONE`), so `before_bind`
> and `on_connect` encrypt the connection but do not authenticate the server. To
> enable verification against a CA bundle, set `server_tls_kwargs` accordingly:

```python
import ssl
# example - encrypt AND verify the server certificate
c.LDAPAuthenticator.server_tls_kwargs = {
    'validate': ssl.CERT_REQUIRED,
    'ca_certs_file': '/etc/ssl/certs/ca-bundle.pem',
}
```

<dl>
  <dt>LDAPAuthenticator.server_use_ssl</dt>
  <dd><strong>Deprecated since 1.0.</strong> Boolean specifying if the connection is on a secure port. Setting <code>server_use_ssl=True</code> is equivalent to configuring <code>server_tls_strategy='on_connect'</code>. Use <code>server_tls_strategy</code> instead (defaults to False).</dd>
</dl>

<dl>
  <dt>LDAPAuthenticator.server_connect_timeout</dt>
  <dd>Timeout in seconds permitted when establishing an ldap connection before raising an exception (defaults to None).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.server_connect_timeout = 10
```

<dl>
  <dt>LDAPAuthenticator.server_receive_timeout</dt>
  <dd>Timeout in seconds permitted for responses from established ldap connections before raising an exception (defaults to None).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.server_receive_timeout = 10
```

<dl>
  <dt>LDAPAuthenticator.server_pool_strategy</dt>
  <dd>Available Pool HA strategies (defaults to 'FIRST').</dd>
</dl>

  - FIRST: Gets the first server in the pool, if 'server_pool_active' is set to True gets the first available server.
  - ROUND_ROBIN: Each time the connection is open the subsequent server in the pool is used. If 'server_pool_active' is set to True unavailable servers will be discarded.
  - RANDOM: each time the connection is open a random server is chosen in the pool. If 'server_pool_active' is set to True unavailable servers will be discarded.

```python
# example
c.LDAPAuthenticator.server_pool_strategy = 'FIRST'
```

<dl>
  <dt>LDAPAuthenticator.server_pool_active</dt>
  <dd>If True the ServerPool strategy will check for server availability. Set to Integer for maximum number of cycles to try before giving up (defaults to True).</dd>
</dl>

```python
# example - boolean
c.LDAPAuthenticator.server_pool_active = True

# example - maximum number of tries
c.LDAPAuthenticator.server_pool_active = 3
```

<dl>
  <dt>LDAPAuthenticator.server_pool_exhaust</dt>
  <dd>If True, any inactive servers will be removed from the pool. If set to an Integer, this will be the number of seconds an unreachable server is considered offline. When this timeout expires the server is reinserted in the pool and checked again for availability (defaults to False).</dd>
</dl>

```python
# example - boolean
c.LDAPAuthenticator.server_pool_exhaust = True

# example - offline timeout
c.LDAPAuthenticator.server_pool_exhaust = 600
```

#### Bind parameters

<dl>
  <dt>LDAPAuthenticator.bind_dn_template</dt>
  <dd>Template(s) from which to construct the full DN used to bind directly to the LDAP server as the authenticating user, bypassing the service-account search. '{username}' is replaced with the authenticating username. When set, authentication uses the direct-bind strategy. Accepts a single string or a list of templates (tried in order until one binds). Defaults to None.</dd>
</dl>

```python
# example - single template
c.LDAPAuthenticator.bind_dn_template = 'uid={username},ou=people,dc=example,dc=org'

# example - multiple templates
c.LDAPAuthenticator.bind_dn_template = [
    'uid={username},ou=people,dc=example,dc=org',
    'uid={username},ou=developers,dc=example,dc=org',
]
```

<dl>
  <dt>LDAPAuthenticator.bind_user_dn</dt>
  <dd>The account of the user to log in for simple bind (defaults to None). Required for the search-bind strategy.</dd>
</dl>

```python
# example - freeipa
c.LDAPAuthenticator.bind_user_dn = 'uid=imauser,cn=users,cn=accounts,dc=example,dc=com'

# example - Active Directory
c.LDAPAuthenticator.bind_user_dn = 'CN=imauser,CN=Users,DC=example,DC=com'
```

<dl>
  <dt>LDAPAuthenticator.bind_user_password</dt>
  <dd>The password of the user for simple bind (defaults to None). Required for the search-bind strategy.</dd>
</dl>

```python
# example
c.LDAPAuthenticator.bind_user_password = 'password'
```

#### User and group parameters

<dl>
  <dt>LDAPAuthenticator.user_search_base</dt>
  <dd>The location in the Directory Information Tree where the user search will start.</dd>
</dl>

```python
# example - freeipa
c.LDAPAuthenticator.user_search_base = 'cn=users,cn=accounts,dc=example,dc=com'

# example - active directory
c.LDAPAuthenticator.user_search_base = 'CN=Users,DC=example,DC=com'
```

<dl>
  <dt>LDAPAuthenticator.user_search_filter</dt>
  <dd>LDAP search filter to validate that the authenticating user exists within the organization. Search filters containing '{username}' will have that value substituted with the username of the authenticating user.</dd>
</dl>

```python
# example - freeipa
c.LDAPAuthenticator.user_search_filter = '(&(objectClass=person)(uid={username}))'

# example - active directory
c.LDAPAuthenticator.user_search_filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))'
```

<dl>
  <dt>LDAPAuthenticator.user_membership_attribute</dt>
  <dd>LDAP Attribute used to associate user group membership (defaults to 'memberOf').</dd>
</dl>

```python
# example
c.LDAPAuthenticator.user_membership_attribute = 'memberOf'
```

<dl>
  <dt>LDAPAuthenticator.group_search_base</dt>
  <dd>The location in the Directory Information Tree where the group search will start.
  Search string containing '{group}' will be substituted with entries taken from
  allowed_groups</dd>
</dl>

```python
# example - freeipa
c.LDAPAuthenticator.group_search_base = 'cn=groups,cn=accounts,dc=example,dc=com'

# example - active directory
c.LDAPAuthenticator.group_search_base = 'CN=Groups,DC=example,DC=com'
```

<dl>
  <dt>LDAPAuthenticator.group_search_filter</dt>
  <dd>LDAP search filter to return members of groups defined in the allowed_groups parameter. Search filters containing '{group}' will have that value substituted with the group dns provided in the allowed_groups parameter.</dd>
</dl>

```python
# example - freeipa
c.LDAPAuthenticator.group_search_filter = '(&(objectClass=ipausergroup)(memberOf={group}))'

# example - active directory
c.LDAPAuthenticator.group_search_filter = '(&(objectClass=group)(memberOf={group}))'
```

<dl>
  <dt>LDAPAuthenticator.allowed_groups</dt>
  <dd>List of LDAP group DNs that users must be a member of in order to be granted login. If left undefined or set to None, allowed_groups will be short-circuited and all users will be allowed (defaults to None).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.allowed_groups = ['cn=jupyterhub-users,cn=groups,cn=accounts,dc=example,dc=com']
```

<dl>
  <dt>LDAPAuthenticator.allow_nested_groups</dt>
  <dd>Boolean allowing for recursive search of members within nested groups of
  allowed_groups (defaults to False).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.allow_nested_groups = True
```

<dl>
  <dt>LDAPAuthenticator.username_pattern</dt>
  <dd>Regular expression pattern that all valid usernames must match. If a username
  does not match the pattern specified here, authentication will not be attempted.
  If not set, allow any username (defaults to None).</dd>
</dl>

```python
# example - freeipa
c.LDAPAuthenticator.username_pattern = '[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?'

# example - active directory
c.LDAPAuthenticator.username_pattern = '[a-zA-Z0-9_.][a-zA-Z0-9_.-]{8,20}[a-zA-Z0-9_.$-]?'
```

#### Home directory and auth_state parameters

<dl>
  <dt>LDAPAuthenticator.create_user_home_dir</dt>
  <dd>Boolean allowing for user home directory to be created at login</dd>
</dl>

```python
# example
c.LDAPAuthenticator.create_user_home_dir = True
```

<dl>
  <dt>LDAPAuthenticator.create_user_home_dir_cmd</dt>
  <dd>Command used when creating a user home directory as a list of strings. The
  username will be appended as the final argument. Defaults
  to `mkhomedir_helper` on linux systems.</dd>
</dl>

```python
# example
c.LDAPAuthenticator.create_user_home_dir_cmd = ['mkhomedir_helper']
```

<dl>
  <dt>LDAPAuthenticator.auth_state_attributes</dt>
  <dd>List of LDAP attributes to fetch for the authenticating user and expose to JupyterHub as <code>auth_state</code>. When set, authentication returns a mapping of the requested attributes. Requires <code>Authenticator.enable_auth_state = True</code> to be persisted (defaults to an empty list).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.auth_state_attributes = ['mail', 'displayName']
```

### Migrating from 0.x

Version 1.0 is backward compatible — existing configurations continue to work.
Two changes are worth noting:

- `server_use_ssl` is **deprecated** in favor of `server_tls_strategy`. Setting
  `server_use_ssl = True` still works but now emits a warning and is translated to
  `server_tls_strategy = 'on_connect'`. Note the new default `server_tls_strategy`
  is `before_bind` (STARTTLS); if you relied on the previous plaintext default,
  set `server_tls_strategy = 'insecure'` explicitly.
- The authenticator is now `async`, requiring **JupyterHub >= 2.0**.

### Examples

##### FreeIPA Integration

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

##### Active Directory Integration

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

##### OpenLDAP Integration (direct-bind)

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
