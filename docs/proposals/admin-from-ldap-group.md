# Proposal: Grant JupyterHub admin from an LDAP group

**Status:** Proposed (not yet implemented)
**Tracking issue:** [#18](https://github.com/hansohn/jupyterhub-ldap-authenticator/issues/18)
**Scope owner:** TBD

## Motivation

Operators currently grant JupyterHub admin rights with a static list:

```python
c.Authenticator.admin_users = {'admin1', 'admin2', 'admin3'}
```

This has to be maintained by hand and duplicates information that already lives
in the directory. The request (issue #18) is to derive admin status from
membership in an LDAP **admin group**, so that adding/removing an admin is done
once, in the directory.

## Design

The plugin already resolves a user's group membership during authentication
(`user_membership_attribute`, `allowed_groups`, and nested-group expansion via
`get_nested_groups`). Admin resolution reuses exactly that machinery.

### New configuration

```python
# groups whose members are granted JupyterHub admin
c.LDAPAuthenticator.admin_groups = ['cn=jupyterhub-admins,ou=groups,dc=example,dc=org']
```

- `admin_groups` — `Union([Unicode(), List()])`, default `None` (feature off).
- Honors `allow_nested_groups` (a member of a nested admin group is an admin),
  reusing `get_nested_groups`.

### How admin is signaled to JupyterHub

JupyterHub reads admin status from the `authenticate()` return value: when it
returns a dict, an `admin` key (`True`/`False`) sets the user's admin flag.
`authenticate()` already returns a dict when `auth_state_attributes` is set, so
the mechanism is in place.

- When `admin_groups` is configured, `authenticate()` returns a dict and sets
  `admin=True/False` based on the intersection of the user's groups with
  `admin_groups` (nested-expanded when enabled).
- Setting `admin=False` explicitly also lets the directory **demote** a user who
  was previously an admin — a nice property the static list can't offer.
- When `admin_groups` is not configured, behavior is unchanged (returns the bare
  username or the existing auth_state dict, with no `admin` key).

### Integration points

- **`_build_auth_response`** — extend to accept/attach an `admin` flag, so both
  the search-bind and direct-bind paths return it consistently.
- **`_authenticate_search_bind` / `_authenticate_direct_bind`** — compute admin
  membership from the already-fetched group attributes (search-bind) or the BASE
  read (direct-bind); no extra LDAP round-trip in the common case.
- A small shared helper (mirroring `_user_allowed`) computes group intersection
  for admin, reusing nested-group expansion.

## Interaction with `Authenticator.admin_users`

`admin_groups` is additive: a user is admin if they are in `admin_users` **or**
in an `admin_group`. This matches operator expectations and keeps the static
list working for break-glass accounts.

## Testing

- Unit tests (extend the existing in-memory LDAP fake): admin via direct group
  membership; admin via nested group; non-admin user gets `admin=False`;
  `admin_groups` unset leaves the return value unchanged (backward compatible);
  interaction with `admin_users`.
- No new infrastructure required.

## Effort & risk

- **Effort:** Small–Medium. Reuses existing group resolution; the return-shape
  change is already established by `auth_state_attributes`.
- **Risk:** Low. Fully opt-in; defaults preserve current behavior.
- **Note:** requires `enable_auth_state` semantics only if combined with
  auth_state; admin via dict return works independently.

## Recommendation

Reasonable, low-risk, and high-value for directory-driven administration.
Implement after the core modernization (#23) lands. Backward compatible.
