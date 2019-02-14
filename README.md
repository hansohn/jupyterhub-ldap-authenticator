# jupyterhub-ldap-authenticator

LDAP Authenticator plugin for [JupyterHub](https://github.com/jupyterhub/jupyterhub).
This project was written with Enterprise LDAP integration in mind and includes the
following features:

- Supports multiple LDAP servers and allows for configuration of `server_pool_strategy`
- Uses single read-only LDAP connection per authentication request
- Verifies authenticating user exists in LDAP and is a member of `allowed_groups`
    before testing authentication
- Supports using nested groups in `allowed_groups` list
- Supports domain user home directory creation at login

This project was inspired by the [ldapauthenticator](https://github.com/jupyterhub/ldapauthenticator) project

## Installation

Install with pip:

```
pip install jupyterhub-ldap-authenticator
```

## Configuration

To enable LDAPAuthenticator, add the following line to the Jupyterhub config file and extend configuration with the parameters listed below.

```python
c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
```

<dl>
  <dt>LDAPAuthenticator.server_hosts</dt>
  <dd>List of Names, IPs, or the complete URLs in the scheme://hostname:hostport format of the server (required).</dd>
</dl>

```python
# example- list of complete urls
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
  <dt>LDAPAuthenticator.server_use_ssl</dt>
  <dd>Boolean specifying if the connection is on a secure port (defaults to False).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.server_use_ssl = True
```

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

<dl>
  <dt>LDAPAuthenticator.bind_user_dn</dt>
  <dd>The account of the user to log in for simple bind (defaults to None).</dd>
</dl>

```python
# example - freeipa
c.LDAPAuthenticator.bind_user_dn = 'uid=imauser,cn=users,cn=accounts,dc=example,dc=com'

# example - Active Directory
c.LDAPAuthenticator.bind_user_dn = 'CN=imauser,CN=Users,DC=example,DC=com'
```

<dl>
  <dt>LDAPAuthenticator.bind_user_password</dt>
  <dd>The password of the user for simple bind (defaults to None).</dd>
</dl>

```python
# example
c.LDAPAuthenticator.bind_user_password = 'password'
```

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
  <dd>Command used when creating a userhome directory as a list of strings. For
  each element in the list, the string USERNAME will be replaced with the user's
  username. The username will also be appended as the final argument. Defaults
  to `mkhomedir_helper` on linux systems.</dd>
</dl>

```python
# example
c.LDAPAuthenticator.create_user_home_dir_cmd = ['mkhomedir_helper']
```


## Examples

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
c.LDAPAuthenticator.user_search_filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))
c.LDAPAuthenticator.user_membership_attribute = 'memberOf'
c.LDAPAuthenticator.group_search_base = 'CN=Groups,DC=example,DC=com'
c.LDAPAuthenticator.group_search_filter = '(&(objectClass=group)(memberOf={group}))'
c.LDAPAuthenticator.allowed_groups = ['CN=jupyterhub-users,CN=Groups,DC=example,DC=com']
c.LDAPAuthenticator.allow_nested_groups = True
c.LDAPAuthenticator.username_pattern = '[a-zA-Z0-9_.][a-zA-Z0-9_.-]{8,20}[a-zA-Z0-9_.$-]?'
c.LDAPAuthenticator.create_user_home_dir = True
c.LDAPAuthenticator.create_user_home_dir_cmd = ['mkhomedir_helper']
```

##### OpenLDAP Integration

Because OpenLDAP does not natively support the memberOf attribute in their user objects, the `allowed_groups` scoping has been short-circuited in the following example:

```python
# openldap example
c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
c.LDAPAuthenticator.server_hosts = ['ldaps://ldap1.example.com:636', 'ldaps://ldap2.example.com:636']
c.LDAPAuthenticator.bind_user_dn = 'uid=imauser,ou=People,dc=example,dc=com'
c.LDAPAuthenticator.bind_user_password = 'imapassword'
c.LDAPAuthenticator.user_search_base = 'ou=People,dc=example,dc=com'
c.LDAPAuthenticator.user_search_filter = '(&(objectClass=posixAccount)(uid={username}))'
c.LDAPAuthenticator.username_pattern = '[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?'
c.LDAPAuthenticator.create_user_home_dir = True
c.LDAPAuthenticator.create_user_home_dir_cmd = ['mkhomedir_helper']
```
