# Docker demo environment

A self-contained [Docker Compose](https://docs.docker.com/compose/) stack for
exercising `jupyterhub-ldap-authenticator` end to end:

- **openldap** — an [OpenLDAP](https://github.com/osixia/docker-openldap) server
  seeded with demo users and groups (with the `memberof` overlay enabled).
- **jupyterhub** — JupyterHub with the local plugin installed from source,
  configured to authenticate against the LDAP server.

The plugin is installed from the repository source (not PyPI), so this is a
faithful test of the current working tree.

## Quick start

```bash
cd examples/docker
docker compose up --build -d
```

Then open <http://localhost:8000> and log in. Stop and reset with:

```bash
docker compose down -v   # -v also clears the seeded LDAP data
```

## Demo accounts

| Username | Password        | Groups                                   |
| -------- | --------------- | ---------------------------------------- |
| `alice`  | `alicepassword` | `jupyterhub-users` (direct member)       |
| `carol`  | `carolpassword` | `data-scientists` → nested under `jupyterhub-users` |
| `bob`    | `bobpassword`   | none                                     |

The LDAP admin bind is `cn=admin,dc=example,dc=org` / `admin`.

## Trying each feature

Behavior is controlled by two environment variables consumed by
[`jupyterhub_config.py`](jupyterhub/jupyterhub_config.py).

### Search-bind (default)

Connects as a service account, searches for the user, then verifies the password.

```bash
docker compose up --build -d
# all three users authenticate (no group restriction)
```

### Direct-bind

Binds directly as the user via `bind_dn_template` — no service account.

```bash
LDAP_STRATEGY=direct_bind docker compose up -d
```

### Group access control + nested groups

Restricts login to members of `jupyterhub-users`, resolving nested groups.

```bash
LDAP_ENABLE_GROUPS=true docker compose up -d
# alice (direct) and carol (nested) succeed; bob is denied
```

The variables combine freely, e.g.
`LDAP_STRATEGY=direct_bind LDAP_ENABLE_GROUPS=true docker compose up -d`.

## Editing the configuration

`jupyterhub_config.py` is mounted into the container, so after editing it you
only need to restart the hub (no rebuild):

```bash
docker compose restart jupyterhub
```

Editing the plugin source (`../../ldapauthenticator/`) does require a rebuild:

```bash
docker compose up --build -d
```

## Notes

- This stack is for **local testing only**. It uses plaintext LDAP
  (`server_tls_strategy = 'insecure'`), demo passwords, and a hard-coded
  `JUPYTERHUB_CRYPT_KEY`. Do not use any of it in production.
- Group membership relies on OpenLDAP's `memberof` overlay, which populates the
  `memberOf` attribute. The overlay ignores dangling references, so in
  [`ldap/bootstrap.ldif`](ldap/bootstrap.ldif) a child group is defined **before**
  the parent that references it.
